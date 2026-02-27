// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"bytes"
	"testing"
)

func TestRTPHeaderEncodeDecode(t *testing.T) {
	h := RTPHeader{
		Version:        RTPVersion,
		Padding:        false,
		Extension:      false,
		CSRCCount:      2,
		Marker:         true,
		PayloadType:    RTPPayloadTypeOpus,
		SequenceNumber: 321,
		Timestamp:      4567,
		SSRC:           0x12345678,
		CSRC:           []uint32{0x11111111, 0x22222222},
	}

	buf := make([]byte, h.Size())
	if _, err := h.Encode(buf); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	decoded, err := DecodeRTPHeader(buf)
	if err != nil {
		t.Fatalf("DecodeRTPHeader failed: %v", err)
	}
	if decoded.SequenceNumber != h.SequenceNumber || decoded.Timestamp != h.Timestamp || decoded.SSRC != h.SSRC {
		t.Fatalf("decoded mismatch: %+v vs %+v", decoded, h)
	}
	if len(decoded.CSRC) != 2 || decoded.CSRC[0] != h.CSRC[0] || decoded.CSRC[1] != h.CSRC[1] {
		t.Fatalf("decoded csrc mismatch: %+v vs %+v", decoded.CSRC, h.CSRC)
	}
}

func TestRTPPacketEncodeDecode(t *testing.T) {
	s := NewRTPPacketSession(0x9abcdeff, RTPPayloadTypeOpus, 16000, 320)
	pkt := s.CreatePacket([]byte("opus-frame"), false)
	encoded := pkt.Encode()
	decoded, err := DecodeRTPPacket(encoded)
	if err != nil {
		t.Fatalf("DecodeRTPPacket failed: %v", err)
	}
	if decoded.Header.PayloadType != RTPPayloadTypeOpus {
		t.Fatalf("unexpected payload type: %d", decoded.Header.PayloadType)
	}
	if !bytes.Equal(decoded.Payload, []byte("opus-frame")) {
		t.Fatalf("unexpected payload: %q", decoded.Payload)
	}
}

func TestRTPPacketSessionSequenceTimestamp(t *testing.T) {
	s := NewRTPPacketSession(0x10101010, RTPPayloadTypeOpus, 16000, 320)
	first := s.CreatePacket([]byte{1}, false)
	second := s.CreatePacket([]byte{2}, true)
	if first.Header.SequenceNumber != 0 || second.Header.SequenceNumber != 1 {
		t.Fatalf("unexpected sequence numbers: %d %d", first.Header.SequenceNumber, second.Header.SequenceNumber)
	}
	if first.Header.Timestamp != 0 || second.Header.Timestamp != 320 {
		t.Fatalf("unexpected timestamps: %d %d", first.Header.Timestamp, second.Header.Timestamp)
	}
	if !second.Header.Marker {
		t.Fatalf("expected marker bit on second packet")
	}
}
