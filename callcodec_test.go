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
)

func TestMuLawCodecRoundTrip(t *testing.T) {
	codec := MuLawCodec{}
	pcm := []byte{0x00, 0x00, 0x10, 0x27, 0xF0, 0xD8}
	encoded, err := codec.Encode("call", pcm)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	decoded, err := codec.Decode("call", encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	if len(decoded) != len(pcm) {
		t.Fatalf("decoded length mismatch: got %d want %d", len(decoded), len(pcm))
	}
}

func TestBufferedDeviceAdapters(t *testing.T) {
	ctx := context.Background()
	audioSrcCh := make(chan []byte, 1)
	audioSinkCh := make(chan []byte, 1)
	audioSrcCh <- []byte("mic")

	source := BufferedAudioSource{Frames: audioSrcCh}
	sink := BufferedAudioSink{Frames: audioSinkCh}

	frame, err := source.ReadAudioFrame(ctx, "call")
	if err != nil {
		t.Fatalf("ReadAudioFrame failed: %v", err)
	}
	if err = sink.HandleAudioFrame(ctx, "call", frame); err != nil {
		t.Fatalf("HandleAudioFrame failed: %v", err)
	}
	got := <-audioSinkCh
	if !bytes.Equal(got, []byte("mic")) {
		t.Fatalf("unexpected sink frame: %q", got)
	}
}
