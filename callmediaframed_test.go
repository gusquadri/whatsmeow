// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"bytes"
	"context"
	"testing"

	"go.mau.fi/whatsmeow/types"
)

type testAudioSink struct {
	callID string
	frame  []byte
}

func (s *testAudioSink) HandleAudioFrame(_ context.Context, callID string, frame []byte) error {
	s.callID = callID
	s.frame = append([]byte(nil), frame...)
	return nil
}

type testVideoSink struct {
	callID string
	frame  []byte
}

func (s *testVideoSink) HandleVideoFrame(_ context.Context, callID string, frame []byte) error {
	s.callID = callID
	s.frame = append([]byte(nil), frame...)
	return nil
}

func TestFramedMediaPayloadRoundTrip(t *testing.T) {
	input := []byte{1, 2, 3}
	encoded := BuildFramedMediaPayload(MediaPayloadAudio, input)
	kind, decoded, err := ParseFramedMediaPayload(encoded)
	if err != nil {
		t.Fatalf("ParseFramedMediaPayload failed: %v", err)
	}
	if kind != MediaPayloadAudio {
		t.Fatalf("unexpected kind: %v", kind)
	}
	if !bytes.Equal(decoded, input) {
		t.Fatalf("unexpected decoded payload")
	}
}

func TestFramedCallMediaEngineRoutesAudioAndVideo(t *testing.T) {
	audioSink := &testAudioSink{}
	videoSink := &testVideoSink{}
	engine := NewFramedCallMediaEngine(CallMediaIO{AudioSink: audioSink, VideoSink: videoSink})

	info := &types.CallInfo{CallID: "call-framed-1"}
	if err := engine.Start(context.Background(), info, &DerivedCallKeys{}); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	audioFrame := []byte("audio-frame")
	if err := engine.HandleIncomingPayload(context.Background(), info, BuildFramedMediaPayload(MediaPayloadAudio, audioFrame)); err != nil {
		t.Fatalf("HandleIncomingPayload audio failed: %v", err)
	}
	if audioSink.callID != info.CallID || !bytes.Equal(audioSink.frame, audioFrame) {
		t.Fatalf("unexpected audio sink payload")
	}

	videoFrame := []byte("video-frame")
	if err := engine.HandleIncomingPayload(context.Background(), info, BuildFramedMediaPayload(MediaPayloadVideo, videoFrame)); err != nil {
		t.Fatalf("HandleIncomingPayload video failed: %v", err)
	}
	if videoSink.callID != info.CallID || !bytes.Equal(videoSink.frame, videoFrame) {
		t.Fatalf("unexpected video sink payload")
	}

	if err := engine.Stop(context.Background(), info); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}
