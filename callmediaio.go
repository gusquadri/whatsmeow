// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import "context"

// AudioFrameSink receives decoded incoming audio frames for a call.
type AudioFrameSink interface {
	HandleAudioFrame(ctx context.Context, callID string, frame []byte) error
}

// VideoFrameSink receives decoded incoming video frames for a call.
type VideoFrameSink interface {
	HandleVideoFrame(ctx context.Context, callID string, frame []byte) error
}

// AudioFrameSource provides outgoing audio frames for a call.
type AudioFrameSource interface {
	ReadAudioFrame(ctx context.Context, callID string) ([]byte, error)
}

// VideoFrameSource provides outgoing video frames for a call.
type VideoFrameSource interface {
	ReadVideoFrame(ctx context.Context, callID string) ([]byte, error)
}

// CallMediaIO contains pluggable media IO adapters.
type CallMediaIO struct {
	AudioSink   AudioFrameSink
	VideoSink   VideoFrameSink
	AudioSource AudioFrameSource
	VideoSource VideoFrameSource
}

// CallMediaIOConfigurable is implemented by media engines that can consume external media IO adapters.
type CallMediaIOConfigurable interface {
	SetMediaIO(io CallMediaIO)
}
