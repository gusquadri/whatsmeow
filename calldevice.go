// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"fmt"
)

// BufferedAudioSource is a channel-backed AudioFrameSource adapter.
type BufferedAudioSource struct {
	Frames <-chan []byte
}

func (s BufferedAudioSource) ReadAudioFrame(ctx context.Context, _ string) ([]byte, error) {
	if s.Frames == nil {
		return nil, fmt.Errorf("audio source channel is nil")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case frame, ok := <-s.Frames:
		if !ok {
			return nil, fmt.Errorf("audio source closed")
		}
		out := make([]byte, len(frame))
		copy(out, frame)
		return out, nil
	}
}

// BufferedVideoSource is a channel-backed VideoFrameSource adapter.
type BufferedVideoSource struct {
	Frames <-chan []byte
}

func (s BufferedVideoSource) ReadVideoFrame(ctx context.Context, _ string) ([]byte, error) {
	if s.Frames == nil {
		return nil, fmt.Errorf("video source channel is nil")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case frame, ok := <-s.Frames:
		if !ok {
			return nil, fmt.Errorf("video source closed")
		}
		out := make([]byte, len(frame))
		copy(out, frame)
		return out, nil
	}
}

// BufferedAudioSink is a channel-backed AudioFrameSink adapter.
type BufferedAudioSink struct {
	Frames chan<- []byte
}

func (s BufferedAudioSink) HandleAudioFrame(ctx context.Context, _ string, frame []byte) error {
	if s.Frames == nil {
		return fmt.Errorf("audio sink channel is nil")
	}
	out := make([]byte, len(frame))
	copy(out, frame)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case s.Frames <- out:
		return nil
	}
}

// BufferedVideoSink is a channel-backed VideoFrameSink adapter.
type BufferedVideoSink struct {
	Frames chan<- []byte
}

func (s BufferedVideoSink) HandleVideoFrame(ctx context.Context, _ string, frame []byte) error {
	if s.Frames == nil {
		return fmt.Errorf("video sink channel is nil")
	}
	out := make([]byte, len(frame))
	copy(out, frame)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case s.Frames <- out:
		return nil
	}
}
