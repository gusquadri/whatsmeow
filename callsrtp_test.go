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

func testSRTPKeying() SRTPKeyingMaterial {
	return SRTPKeyingMaterial{
		MasterKey:  [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		MasterSalt: [14]byte{17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30},
	}
}

func TestSRTPRoundTrip(t *testing.T) {
	keying := testSRTPKeying()
	send, err := NewSRTPCryptoContext(keying)
	if err != nil {
		t.Fatalf("NewSRTPCryptoContext(send) failed: %v", err)
	}
	recv, err := NewSRTPCryptoContext(keying)
	if err != nil {
		t.Fatalf("NewSRTPCryptoContext(recv) failed: %v", err)
	}

	h := NewRTPHeader(RTPPayloadTypeOpus, 1000, 16000, 0x12345678)
	pkt := RTPPacket{Header: h, Payload: []byte("audio-data")}
	encrypted, err := send.Protect(pkt)
	if err != nil {
		t.Fatalf("Protect failed: %v", err)
	}
	if bytes.Contains(encrypted, []byte("audio-data")) {
		t.Fatalf("encrypted packet unexpectedly contains plaintext payload")
	}
	decrypted, err := recv.Unprotect(encrypted)
	if err != nil {
		t.Fatalf("Unprotect failed: %v", err)
	}
	if !bytes.Equal(decrypted.Payload, pkt.Payload) {
		t.Fatalf("payload mismatch: got %q want %q", decrypted.Payload, pkt.Payload)
	}
	if decrypted.Header.SequenceNumber != pkt.Header.SequenceNumber {
		t.Fatalf("sequence mismatch: got %d want %d", decrypted.Header.SequenceNumber, pkt.Header.SequenceNumber)
	}
}

func TestSRTPAuthenticationFailure(t *testing.T) {
	keying := testSRTPKeying()
	send, _ := NewSRTPCryptoContext(keying)
	recv, _ := NewSRTPCryptoContext(keying)

	pkt := RTPPacket{Header: NewRTPHeader(RTPPayloadTypeOpus, 3, 320, 0x11111111), Payload: []byte{9, 8, 7, 6}}
	encrypted, err := send.Protect(pkt)
	if err != nil {
		t.Fatalf("Protect failed: %v", err)
	}
	encrypted[len(encrypted)-1] ^= 0xFF
	if _, err = recv.Unprotect(encrypted); err == nil {
		t.Fatalf("expected auth failure for tampered packet")
	}
}

func TestSRTPSessionRoundTrip(t *testing.T) {
	session, err := NewSRTPSession(testSRTPKeying(), testSRTPKeying())
	if err != nil {
		t.Fatalf("NewSRTPSession failed: %v", err)
	}
	pkt := RTPPacket{Header: NewRTPHeader(RTPPayloadTypeOpus, 65535, 64000, 0x22222222), Payload: []byte("frame")}
	encrypted, err := session.Protect(pkt)
	if err != nil {
		t.Fatalf("Protect failed: %v", err)
	}
	decrypted, err := session.Unprotect(encrypted)
	if err != nil {
		t.Fatalf("Unprotect failed: %v", err)
	}
	if !bytes.Equal(decrypted.Payload, pkt.Payload) {
		t.Fatalf("payload mismatch")
	}
}
