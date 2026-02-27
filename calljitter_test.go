// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"testing"
	"time"
)

func makeRTP(seq uint16, ts uint32) RTPPacket {
	return RTPPacket{Header: NewRTPHeader(RTPPayloadTypeOpus, seq, ts, 0x12345678), Payload: []byte{1, 2, 3}}
}

func TestJitterBufferReorderAndPop(t *testing.T) {
	cfg := DefaultJitterBufferConfig()
	cfg.TargetDelay = 0
	j := NewJitterBuffer(cfg)
	j.Push(makeRTP(1002, 320))
	j.Push(makeRTP(1000, 0))
	j.Push(makeRTP(1001, 160))

	p1 := j.Pop()
	if p1 == nil || p1.Header.SequenceNumber != 1000 {
		t.Fatalf("unexpected first packet: %+v", p1)
	}
	p2 := j.Pop()
	if p2 == nil || p2.Header.SequenceNumber != 1001 {
		t.Fatalf("unexpected second packet: %+v", p2)
	}
	p3 := j.Pop()
	if p3 == nil || p3.Header.SequenceNumber != 1002 {
		t.Fatalf("unexpected third packet: %+v", p3)
	}
}

func TestJitterBufferDuplicateAndExpiry(t *testing.T) {
	cfg := DefaultJitterBufferConfig()
	cfg.TargetDelay = 0
	cfg.MaxAge = 1 * time.Millisecond
	j := NewJitterBuffer(cfg)
	j.Push(makeRTP(10, 0))
	j.Push(makeRTP(10, 0))
	if j.Stats().PacketsDuplicate != 1 {
		t.Fatalf("expected duplicate count 1, got %d", j.Stats().PacketsDuplicate)
	}
	time.Sleep(2 * time.Millisecond)
	if pkt := j.Pop(); pkt != nil {
		t.Fatalf("expected expired packet to be dropped, got %+v", pkt)
	}
	if j.Stats().PacketsDropped == 0 {
		t.Fatalf("expected dropped packets from expiry")
	}
}

func TestJitterBufferWraparoundOrder(t *testing.T) {
	cfg := DefaultJitterBufferConfig()
	cfg.TargetDelay = 0
	j := NewJitterBuffer(cfg)

	// Establish sequencing context first.
	j.Push(makeRTP(65534, 0))
	j.Push(makeRTP(65535, 160))
	p0 := j.Pop()
	if p0 == nil || p0.Header.SequenceNumber != 65534 {
		t.Fatalf("unexpected primer packet: %+v", p0)
	}

	// Then cross 65535 -> 0 boundary and ensure ordering remains forward.
	j.Push(makeRTP(1, 480))
	j.Push(makeRTP(0, 320))

	p1 := j.Pop()
	if p1 == nil || p1.Header.SequenceNumber != 65535 {
		t.Fatalf("unexpected second packet near wrap: %+v", p1)
	}
	p2 := j.Pop()
	if p2 == nil || p2.Header.SequenceNumber != 0 {
		t.Fatalf("unexpected third packet near wrap: %+v", p2)
	}
	p3 := j.Pop()
	if p3 == nil || p3.Header.SequenceNumber != 1 {
		t.Fatalf("unexpected fourth packet near wrap: %+v", p3)
	}
}
