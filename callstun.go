// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

const (
	stunMagicCookie  = 0x2112A442
	stunFingerprintX = 0x5354554e

	StunMessageBindingRequest  uint16 = 0x0001
	StunMessageBindingResponse uint16 = 0x0101
	StunMessageWhatsAppPing    uint16 = 0x0801
	StunMessageWhatsAppPong    uint16 = 0x0802

	StunAttrUsername            uint16 = 0x0006
	StunAttrMessageIntegrity    uint16 = 0x0008
	StunAttrPriority            uint16 = 0x0024
	StunAttrUseCandidate        uint16 = 0x0025
	StunAttrFingerprint         uint16 = 0x8028
	StunAttrIceControlled       uint16 = 0x8029
	StunAttrIceControlling      uint16 = 0x802A
	StunAttrSenderSubscriptions uint16 = 0x4000
	StunAttrReceiverSub         uint16 = 0x4001
	StunAttrSubAck              uint16 = 0x4002
)

// StunAttribute is a raw STUN attribute.
type StunAttribute struct {
	Type  uint16
	Value []byte
}

// StunMessage is a parsed STUN packet.
type StunMessage struct {
	MessageType   uint16
	TransactionID [12]byte
	Attributes    []StunAttribute
}

// NewStunMessage creates a STUN message with random transaction ID.
func NewStunMessage(messageType uint16) StunMessage {
	msg := StunMessage{MessageType: messageType}
	_, _ = rand.Read(msg.TransactionID[:])
	return msg
}

// Encode serializes a STUN message.
func (m StunMessage) Encode() []byte {
	bodyCap := 0
	for _, attr := range m.Attributes {
		bodyCap += 4 + ((len(attr.Value) + 3) &^ 3)
	}
	body := make([]byte, 0, bodyCap)
	for _, attr := range m.Attributes {
		body = appendStunAttribute(body, attr.Type, attr.Value)
	}
	out := make([]byte, 20+len(body))
	binary.BigEndian.PutUint16(out[0:2], m.MessageType)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(body)))
	binary.BigEndian.PutUint32(out[4:8], stunMagicCookie)
	copy(out[8:20], m.TransactionID[:])
	copy(out[20:], body)
	return out
}

func appendStunAttribute(buf []byte, attrType uint16, value []byte) []byte {
	paddedLen := (len(value) + 3) &^ 3
	start := len(buf)
	buf = append(buf, make([]byte, 4+paddedLen)...)
	binary.BigEndian.PutUint16(buf[start:start+2], attrType)
	binary.BigEndian.PutUint16(buf[start+2:start+4], uint16(len(value)))
	copy(buf[start+4:start+4+len(value)], value)
	return buf
}

// DecodeStunMessage parses STUN packet bytes.
func DecodeStunMessage(data []byte) (StunMessage, error) {
	if len(data) < 20 {
		return StunMessage{}, fmt.Errorf("stun packet too short")
	}
	msgType := binary.BigEndian.Uint16(data[0:2])
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if len(data) < 20+length {
		return StunMessage{}, fmt.Errorf("stun packet length mismatch")
	}
	if binary.BigEndian.Uint32(data[4:8]) != stunMagicCookie {
		return StunMessage{}, fmt.Errorf("invalid stun magic cookie")
	}
	msg := StunMessage{MessageType: msgType}
	copy(msg.TransactionID[:], data[8:20])

	cursor := 20
	end := 20 + length
	for cursor+4 <= end {
		attrType := binary.BigEndian.Uint16(data[cursor : cursor+2])
		attrLen := int(binary.BigEndian.Uint16(data[cursor+2 : cursor+4]))
		cursor += 4
		if cursor+attrLen > end {
			return StunMessage{}, fmt.Errorf("invalid stun attribute length")
		}
		value := make([]byte, attrLen)
		copy(value, data[cursor:cursor+attrLen])
		msg.Attributes = append(msg.Attributes, StunAttribute{Type: attrType, Value: value})
		cursor += (attrLen + 3) &^ 3
	}
	return msg, nil
}

// StunCredentials contain binding auth credentials.
type StunCredentials struct {
	Username     []byte
	IntegrityKey []byte
}

// BuildStunBindingRequest builds a STUN binding request with WhatsApp custom
// sender subscription attribute and RFC5389 integrity/fingerprint attributes.
func BuildStunBindingRequest(creds StunCredentials, senderSubscriptions []byte, tieBreaker uint64, controlling bool) ([]byte, error) {
	msg := NewStunMessage(StunMessageBindingRequest)
	if len(creds.Username) > 0 {
		msg.Attributes = append(msg.Attributes, StunAttribute{Type: StunAttrUsername, Value: append([]byte(nil), creds.Username...)})
	}
	priority := make([]byte, 4)
	// Use the same baseline priority family as relay SDP candidates so bind and
	// ICE checks look consistent to relay-side validators.
	binary.BigEndian.PutUint32(priority, waRelayCandidatePriority)
	msg.Attributes = append(msg.Attributes, StunAttribute{Type: StunAttrPriority, Value: priority})
	if tieBreaker != 0 {
		tie := make([]byte, 8)
		binary.BigEndian.PutUint64(tie, tieBreaker)
		if controlling {
			msg.Attributes = append(msg.Attributes, StunAttribute{Type: StunAttrIceControlling, Value: tie})
		} else {
			msg.Attributes = append(msg.Attributes, StunAttribute{Type: StunAttrIceControlled, Value: tie})
		}
	}
	if controlling {
		// WA relay bind requests from the controlling side carry nomination intent.
		msg.Attributes = append(msg.Attributes, StunAttribute{Type: StunAttrUseCandidate, Value: nil})
	}
	if len(senderSubscriptions) > 0 {
		msg.Attributes = append(msg.Attributes, StunAttribute{Type: StunAttrSenderSubscriptions, Value: append([]byte(nil), senderSubscriptions...)})
	}

	encoded := msg.Encode()
	if len(creds.IntegrityKey) > 0 {
		// Per RFC5389, MESSAGE-INTEGRITY is HMAC over the message up to but
		// excluding the MESSAGE-INTEGRITY attribute itself, with the header
		// length adjusted to include the 24-byte MESSAGE-INTEGRITY TLV.
		binary.BigEndian.PutUint16(encoded[2:4], uint16(len(encoded)-20+24))
		mac := hmac.New(sha1.New, creds.IntegrityKey)
		_, _ = mac.Write(encoded)
		sum := mac.Sum(nil)
		encoded = appendStunAttribute(encoded, StunAttrMessageIntegrity, sum[:20])
	}

	encoded = appendStunFingerprint(encoded)
	return encoded, nil
}

func appendStunFingerprint(packet []byte) []byte {
	packet = appendStunAttribute(packet, StunAttrFingerprint, make([]byte, 4))
	// FINGERPRINT covers the packet up to (but excluding) the FINGERPRINT
	// attribute itself, with the header length including the FINGERPRINT TLV.
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)-20))
	crc := crc32.ChecksumIEEE(packet[:len(packet)-8]) ^ stunFingerprintX
	binary.BigEndian.PutUint32(packet[len(packet)-4:], crc)
	return packet
}

// GetAttribute returns first attribute value of the requested type.
func (m StunMessage) GetAttribute(attrType uint16) ([]byte, bool) {
	for _, attr := range m.Attributes {
		if attr.Type == attrType {
			copied := make([]byte, len(attr.Value))
			copy(copied, attr.Value)
			return copied, true
		}
	}
	return nil, false
}
