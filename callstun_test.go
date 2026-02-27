// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"testing"
)

func TestSenderSubscriptionsEncodeDecode(t *testing.T) {
	data := BuildAudioSenderSubscriptionsWithJID(0x12345678, "user@s.whatsapp.net:0")
	decoded, err := DecodeSenderSubscriptions(data)
	if err != nil {
		t.Fatalf("DecodeSenderSubscriptions failed: %v", err)
	}
	if len(decoded.Senders) != 1 {
		t.Fatalf("unexpected sender count: %d", len(decoded.Senders))
	}
	s := decoded.Senders[0]
	if s.SSRC == nil || *s.SSRC != 0x12345678 {
		t.Fatalf("unexpected ssrc: %+v", s.SSRC)
	}
	if s.StreamLayer == nil || *s.StreamLayer != StreamLayerAudio {
		t.Fatalf("unexpected stream layer: %+v", s.StreamLayer)
	}
	if s.PayloadType == nil || *s.PayloadType != PayloadTypeMedia {
		t.Fatalf("unexpected payload type: %+v", s.PayloadType)
	}
	if s.SenderJID != "user@s.whatsapp.net:0" {
		t.Fatalf("unexpected sender jid: %q", s.SenderJID)
	}
}

func TestBuildStunBindingRequestWithCustomAttrs(t *testing.T) {
	subs := BuildAudioSenderSubscriptions(0xabcdef01)
	packet, err := BuildStunBindingRequest(
		StunCredentials{Username: []byte("auth-token"), IntegrityKey: []byte("relay-key")},
		subs,
		0x0102030405060708,
		true,
	)
	if err != nil {
		t.Fatalf("BuildStunBindingRequest failed: %v", err)
	}
	msg, err := DecodeStunMessage(packet)
	if err != nil {
		t.Fatalf("DecodeStunMessage failed: %v", err)
	}
	if msg.MessageType != StunMessageBindingRequest {
		t.Fatalf("unexpected message type: %x", msg.MessageType)
	}
	if got, ok := msg.GetAttribute(StunAttrUsername); !ok || !bytes.Equal(got, []byte("auth-token")) {
		t.Fatalf("username attribute missing or invalid")
	}
	if got, ok := msg.GetAttribute(StunAttrSenderSubscriptions); !ok || !bytes.Equal(got, subs) {
		t.Fatalf("sender subscription attribute missing or invalid")
	}
	if _, ok := msg.GetAttribute(StunAttrMessageIntegrity); !ok {
		t.Fatalf("expected message-integrity attr")
	}
	if _, ok := msg.GetAttribute(StunAttrFingerprint); !ok {
		t.Fatalf("expected fingerprint attr")
	}
	if _, ok := msg.GetAttribute(StunAttrIceControlling); !ok {
		t.Fatalf("expected ice-controlling attr")
	}
	if _, ok := msg.GetAttribute(StunAttrUseCandidate); !ok {
		t.Fatalf("expected use-candidate attr")
	}
	if got, ok := msg.GetAttribute(StunAttrPriority); !ok || len(got) != 4 || binary.BigEndian.Uint32(got) != waRelayCandidatePriority {
		t.Fatalf("expected relay-priority attribute")
	}

	if err := verifyStunIntegrityAndFingerprint(packet, []byte("relay-key")); err != nil {
		t.Fatalf("integrity/fingerprint verification failed: %v", err)
	}
}

func verifyStunIntegrityAndFingerprint(packet []byte, key []byte) error {
	if len(packet) < 20 {
		return fmt.Errorf("packet too short")
	}
	var (
		cursor   int = 20
		limit        = 20 + int(binary.BigEndian.Uint16(packet[2:4]))
		miOffset     = -1
		miValue  []byte
		fpOffset = -1
		fpValue  []byte
	)
	if limit > len(packet) {
		limit = len(packet)
	}
	for cursor+4 <= limit {
		attrType := binary.BigEndian.Uint16(packet[cursor : cursor+2])
		attrLen := int(binary.BigEndian.Uint16(packet[cursor+2 : cursor+4]))
		valStart := cursor + 4
		valEnd := valStart + attrLen
		if valEnd > limit {
			break
		}
		switch attrType {
		case StunAttrMessageIntegrity:
			miOffset = cursor
			miValue = append([]byte(nil), packet[valStart:valEnd]...)
		case StunAttrFingerprint:
			fpOffset = cursor
			fpValue = append([]byte(nil), packet[valStart:valEnd]...)
		}
		cursor += 4 + ((attrLen + 3) &^ 3)
	}
	if miOffset < 0 || len(miValue) != 20 {
		return fmt.Errorf("missing or invalid message-integrity attribute")
	}
	if fpOffset < 0 || len(fpValue) != 4 {
		return fmt.Errorf("missing or invalid fingerprint attribute")
	}

	hmacInput := append([]byte(nil), packet[:miOffset]...)
	binary.BigEndian.PutUint16(hmacInput[2:4], uint16((miOffset-20)+24))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(hmacInput)
	expectedMI := mac.Sum(nil)
	if !bytes.Equal(miValue, expectedMI[:20]) {
		return fmt.Errorf("message-integrity mismatch")
	}

	crcInput := append([]byte(nil), packet[:fpOffset]...)
	binary.BigEndian.PutUint16(crcInput[2:4], uint16((fpOffset-20)+8))
	expectedFP := crc32.ChecksumIEEE(crcInput) ^ stunFingerprintX
	if binary.BigEndian.Uint32(fpValue) != expectedFP {
		return fmt.Errorf("fingerprint mismatch")
	}
	return nil
}
