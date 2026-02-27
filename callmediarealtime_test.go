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

type testSink struct {
	audio [][]byte
	video [][]byte
}

func (s *testSink) HandleAudioFrame(_ context.Context, _ string, frame []byte) error {
	copied := make([]byte, len(frame))
	copy(copied, frame)
	s.audio = append(s.audio, copied)
	return nil
}

func (s *testSink) HandleVideoFrame(_ context.Context, _ string, frame []byte) error {
	copied := make([]byte, len(frame))
	copy(copied, frame)
	s.video = append(s.video, copied)
	return nil
}

func TestRTPCallMediaEngineRoundTripAndNACKFeedback(t *testing.T) {
	sink := &testSink{}
	cfg := DefaultRTPCallMediaEngineConfig()
	cfg.JitterConfig.TargetDelay = 0
	engine := NewRTPCallMediaEngine(cfg, OpusPacketCodec{}, PassThroughVideoCodec{}, CallMediaIO{AudioSink: sink, VideoSink: sink})

	info := &types.CallInfo{CallID: "call-rtp-engine"}
	key := &CallEncryptionKey{Generation: 1}
	keys := DeriveCallKeys(key)
	if err := engine.Start(context.Background(), info, keys); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer engine.Stop(context.Background(), info)

	out1, err := engine.BuildOutgoingAudioPayload(info.CallID, []byte("f1"))
	if err != nil {
		t.Fatalf("BuildOutgoingAudioPayload #1 failed: %v", err)
	}
	out2, err := engine.BuildOutgoingAudioPayload(info.CallID, []byte("f2"))
	if err != nil {
		t.Fatalf("BuildOutgoingAudioPayload #2 failed: %v", err)
	}
	out3, err := engine.BuildOutgoingAudioPayload(info.CallID, []byte("f3"))
	if err != nil {
		t.Fatalf("BuildOutgoingAudioPayload #3 failed: %v", err)
	}

	if err = engine.HandleIncomingPayload(context.Background(), info, out1); err != nil {
		t.Fatalf("HandleIncomingPayload out1 failed: %v", err)
	}
	if err = engine.HandleIncomingPayload(context.Background(), info, out3); err != nil {
		t.Fatalf("HandleIncomingPayload out3 failed: %v", err)
	}

	feedback := engine.DrainOutgoingControl(info.CallID)
	if len(feedback) == 0 {
		t.Fatalf("expected nack feedback after missing packet")
	}

	if err = engine.HandleIncomingPayload(context.Background(), info, feedback[0]); err != nil {
		t.Fatalf("HandleIncomingPayload nack failed: %v", err)
	}
	feedback = engine.DrainOutgoingControl(info.CallID)
	foundRetransmit := false
	for _, pkt := range feedback {
		if bytes.Equal(pkt, out2) {
			foundRetransmit = true
			break
		}
	}
	if !foundRetransmit {
		t.Fatalf("expected retransmit payload in feedback queue")
	}

	for _, pkt := range [][]byte{out2} {
		if err = engine.HandleIncomingPayload(context.Background(), info, pkt); err != nil {
			t.Fatalf("HandleIncomingPayload retransmit failed: %v", err)
		}
	}

	if len(sink.audio) == 0 {
		t.Fatalf("expected decoded audio frames to be delivered")
	}
}

func TestRTPCallMediaEngineVideoPayload(t *testing.T) {
	sink := &testSink{}
	cfg := DefaultRTPCallMediaEngineConfig()
	engine := NewRTPCallMediaEngine(cfg, OpusPacketCodec{}, PassThroughVideoCodec{}, CallMediaIO{VideoSink: sink})
	info := &types.CallInfo{CallID: "call-video"}
	keys := DeriveCallKeys(&CallEncryptionKey{Generation: 1})
	if err := engine.Start(context.Background(), info, keys); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer engine.Stop(context.Background(), info)

	payload, err := engine.BuildOutgoingVideoPayload(info.CallID, []byte("frame-v"))
	if err != nil {
		t.Fatalf("BuildOutgoingVideoPayload failed: %v", err)
	}
	if err = engine.HandleIncomingPayload(context.Background(), info, payload); err != nil {
		t.Fatalf("HandleIncomingPayload failed: %v", err)
	}
	if len(sink.video) != 1 {
		t.Fatalf("expected one decoded video frame, got %d", len(sink.video))
	}
	if !bytes.Equal(sink.video[0], []byte("frame-v")) {
		t.Fatalf("unexpected video frame: %q", sink.video[0])
	}
}
