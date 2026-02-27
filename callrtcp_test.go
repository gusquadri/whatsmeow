// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import "testing"

func TestRTCPNACKEncodeDecode(t *testing.T) {
	nack := NewRTCPNACK(0x11111111, 0x22222222)
	nack.AddLostSequence(1000)
	nack.AddLostSequence(1001)
	nack.AddLostSequence(1005)
	encoded := nack.Encode()
	decoded, err := DecodeRTCPNACK(encoded)
	if err != nil {
		t.Fatalf("DecodeRTCPNACK failed: %v", err)
	}
	lost := decoded.LostSequences()
	if len(lost) != 3 || lost[0] != 1000 || lost[1] != 1001 || lost[2] != 1005 {
		t.Fatalf("unexpected lost sequences: %#v", lost)
	}
}

func TestNackTrackerDetectsMissing(t *testing.T) {
	tracker := NewNackTracker(128, 3)
	tracker.OnPacketReceived(100)
	miss := tracker.OnPacketReceived(104)
	if len(miss) != 3 || miss[0] != 101 || miss[1] != 102 || miss[2] != 103 {
		t.Fatalf("unexpected missing list: %#v", miss)
	}
	pending := tracker.GetPendingNACKs(10)
	if len(pending) != 3 {
		t.Fatalf("unexpected pending nacks: %#v", pending)
	}
	tracker.OnPacketReceived(102)
	pending = tracker.GetPendingNACKs(10)
	for _, seq := range pending {
		if seq == 102 {
			t.Fatalf("late packet should be removed from pending nack list")
		}
	}
}

func TestRetransmitBufferStoreAndGet(t *testing.T) {
	buf := NewRetransmitBuffer(2)
	buf.Store(1, []byte("a"))
	buf.Store(2, []byte("b"))
	buf.Store(3, []byte("c"))
	if _, ok := buf.Get(1); ok {
		t.Fatalf("expected oldest packet to be evicted")
	}
	if pkt, ok := buf.Get(3); !ok || string(pkt) != "c" {
		t.Fatalf("unexpected packet retrieval: %q ok=%v", pkt, ok)
	}
}

func TestRTCPPLIEncode(t *testing.T) {
	pli := RTCPPLI{SenderSSRC: 0x01020304, MediaSSRC: 0x05060708}
	encoded := pli.Encode()
	if len(encoded) != 12 {
		t.Fatalf("unexpected pli size: %d", len(encoded))
	}
	h, err := DecodeRTCPHeader(encoded)
	if err != nil {
		t.Fatalf("DecodeRTCPHeader failed: %v", err)
	}
	if h.PacketType != RTCPPayloadTypePSFB || h.CountOrFmt != RTCPFmtPLI {
		t.Fatalf("unexpected pli header: %+v", h)
	}
}
