// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"fmt"
	"sync"

	"go.mau.fi/whatsmeow/types"
)

// MediaPayloadKind identifies the media frame kind in framed transport payloads.
type MediaPayloadKind byte

const (
	MediaPayloadUnknown MediaPayloadKind = 0
	MediaPayloadAudio   MediaPayloadKind = 1
	MediaPayloadVideo   MediaPayloadKind = 2
)

// BuildFramedMediaPayload prefixes payload bytes with media kind.
func BuildFramedMediaPayload(kind MediaPayloadKind, payload []byte) []byte {
	out := make([]byte, 1+len(payload))
	out[0] = byte(kind)
	copy(out[1:], payload)
	return out
}

// ParseFramedMediaPayload parses framed payload bytes.
func ParseFramedMediaPayload(payload []byte) (MediaPayloadKind, []byte, error) {
	if len(payload) == 0 {
		return MediaPayloadUnknown, nil, fmt.Errorf("empty media payload")
	}
	kind := MediaPayloadKind(payload[0])
	if kind != MediaPayloadAudio && kind != MediaPayloadVideo {
		return MediaPayloadUnknown, nil, fmt.Errorf("unknown media payload kind %d", payload[0])
	}
	frame := make([]byte, len(payload)-1)
	copy(frame, payload[1:])
	return kind, frame, nil
}

// FramedCallMediaEngine routes framed audio/video payloads to media IO adapters.
//
// Framed payload format:
// - byte 0: kind (1=audio, 2=video)
// - bytes 1..N: opaque media frame data
//
// This engine keeps Phase 3 media pluggable while enabling immediate end-to-end
// packet routing in the existing call manager lifecycle.
type FramedCallMediaEngine struct {
	mu      sync.RWMutex
	active  map[string]struct{}
	mediaIO CallMediaIO
}

// NewFramedCallMediaEngine creates a framed media engine.
func NewFramedCallMediaEngine(io CallMediaIO) *FramedCallMediaEngine {
	return &FramedCallMediaEngine{
		active:  make(map[string]struct{}),
		mediaIO: io,
	}
}

func (e *FramedCallMediaEngine) SetMediaIO(io CallMediaIO) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mediaIO = io
}

func (e *FramedCallMediaEngine) Start(_ context.Context, info *types.CallInfo, _ *DerivedCallKeys) error {
	if info == nil || info.CallID == "" {
		return fmt.Errorf("call info is nil or call id is empty")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.active[info.CallID] = struct{}{}
	return nil
}

func (e *FramedCallMediaEngine) Stop(_ context.Context, info *types.CallInfo) error {
	if info == nil || info.CallID == "" {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.active, info.CallID)
	return nil
}

func (e *FramedCallMediaEngine) HandleIncomingPayload(ctx context.Context, info *types.CallInfo, payload []byte) error {
	if info == nil {
		return fmt.Errorf("call info is nil")
	}
	e.mu.RLock()
	_, active := e.active[info.CallID]
	io := e.mediaIO
	e.mu.RUnlock()
	if !active {
		return fmt.Errorf("call %s media engine not active", info.CallID)
	}

	kind, frame, err := ParseFramedMediaPayload(payload)
	if err != nil {
		return err
	}

	switch kind {
	case MediaPayloadAudio:
		if io.AudioSink != nil {
			return io.AudioSink.HandleAudioFrame(ctx, info.CallID, frame)
		}
	case MediaPayloadVideo:
		if io.VideoSink != nil {
			return io.VideoSink.HandleVideoFrame(ctx, info.CallID, frame)
		}
	}
	return nil
}
