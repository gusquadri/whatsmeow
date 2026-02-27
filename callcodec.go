// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import "fmt"

// CallAudioCodec encodes/decodes call audio frames.
type CallAudioCodec interface {
	Name() string
	Encode(callID string, pcm []byte) ([]byte, error)
	Decode(callID string, payload []byte) ([]byte, error)
}

// CallVideoCodec encodes/decodes call video frames.
type CallVideoCodec interface {
	Name() string
	Encode(callID string, frame []byte) ([]byte, error)
	Decode(callID string, payload []byte) ([]byte, error)
}

// OpusPacketCodec treats source/sink frames as already-encoded Opus packets.
//
// This is the default for WhatsApp audio in the current codebase and lets callers
// provide real capture/decoder pipelines externally while keeping protocol parity.
type OpusPacketCodec struct{}

func (OpusPacketCodec) Name() string { return "opus" }
func (OpusPacketCodec) Encode(_ string, pcm []byte) ([]byte, error) {
	out := make([]byte, len(pcm))
	copy(out, pcm)
	return out, nil
}
func (OpusPacketCodec) Decode(_ string, payload []byte) ([]byte, error) {
	out := make([]byte, len(payload))
	copy(out, payload)
	return out, nil
}

// PassThroughVideoCodec treats frames as pre-encoded payload bytes.
type PassThroughVideoCodec struct{}

func (PassThroughVideoCodec) Name() string { return "passthrough-video" }
func (PassThroughVideoCodec) Encode(_ string, frame []byte) ([]byte, error) {
	out := make([]byte, len(frame))
	copy(out, frame)
	return out, nil
}
func (PassThroughVideoCodec) Decode(_ string, payload []byte) ([]byte, error) {
	out := make([]byte, len(payload))
	copy(out, payload)
	return out, nil
}

// MuLawCodec is a concrete PCM16<->G.711 µ-law codec.
// Input/output PCM is little-endian 16-bit mono.
type MuLawCodec struct{}

func (MuLawCodec) Name() string { return "pcmu" }

func (MuLawCodec) Encode(_ string, pcm []byte) ([]byte, error) {
	if len(pcm)%2 != 0 {
		return nil, fmt.Errorf("pcm16 payload has odd length: %d", len(pcm))
	}
	out := make([]byte, len(pcm)/2)
	for i := 0; i < len(out); i++ {
		sample := int16(uint16(pcm[i*2]) | uint16(pcm[i*2+1])<<8)
		out[i] = linearToMuLaw(sample)
	}
	return out, nil
}

func (MuLawCodec) Decode(_ string, payload []byte) ([]byte, error) {
	out := make([]byte, len(payload)*2)
	for i, b := range payload {
		sample := muLawToLinear(b)
		out[i*2] = byte(sample)
		out[i*2+1] = byte(sample >> 8)
	}
	return out, nil
}

func linearToMuLaw(sample int16) byte {
	const (
		bias = 0x84
		clip = 32635
	)
	sign := byte(0)
	s := int(sample)
	if s < 0 {
		sign = 0x80
		s = -s
	}
	if s > clip {
		s = clip
	}
	s += bias
	exponent := 7
	for expMask := 0x4000; (s&expMask) == 0 && exponent > 0; expMask >>= 1 {
		exponent--
	}
	mantissa := (s >> (exponent + 3)) & 0x0F
	return ^(sign | byte(exponent<<4) | byte(mantissa))
}

func muLawToLinear(mu byte) int16 {
	mu = ^mu
	sign := mu & 0x80
	exponent := (mu >> 4) & 0x07
	mantissa := mu & 0x0F
	sample := ((int(mantissa) << 3) + 0x84) << exponent
	sample -= 0x84
	if sign != 0 {
		sample = -sample
	}
	return int16(sample)
}
