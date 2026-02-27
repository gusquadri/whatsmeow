// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"fmt"
	"io"
)

const (
	// RTPVersion is the only supported RTP version.
	RTPVersion = 2

	// RTPPayloadTypeOpus is the dynamic payload type used by WhatsApp voice payloads.
	RTPPayloadTypeOpus = 120
)

// RTPHeader is the RTP packet header per RFC 3550.
type RTPHeader struct {
	Version        uint8
	Padding        bool
	Extension      bool
	CSRCCount      uint8
	Marker         bool
	PayloadType    uint8
	SequenceNumber uint16
	Timestamp      uint32
	SSRC           uint32
	CSRC           []uint32
}

// NewRTPHeader creates a new default RTP header.
func NewRTPHeader(payloadType uint8, sequence uint16, timestamp uint32, ssrc uint32) RTPHeader {
	return RTPHeader{
		Version:        RTPVersion,
		PayloadType:    payloadType,
		SequenceNumber: sequence,
		Timestamp:      timestamp,
		SSRC:           ssrc,
	}
}

// Size returns the serialized header size.
func (h RTPHeader) Size() int {
	return 12 + int(h.CSRCCount)*4
}

// Encode writes the RTP header into buf and returns bytes written.
func (h RTPHeader) Encode(buf []byte) (int, error) {
	headerSize := h.Size()
	if len(buf) < headerSize {
		return 0, io.ErrShortBuffer
	}

	buf[0] = (h.Version << 6) | (boolToByte(h.Padding) << 5) | (boolToByte(h.Extension) << 4) | (h.CSRCCount & 0x0F)
	buf[1] = (boolToByte(h.Marker) << 7) | (h.PayloadType & 0x7F)
	buf[2] = byte(h.SequenceNumber >> 8)
	buf[3] = byte(h.SequenceNumber)
	buf[4] = byte(h.Timestamp >> 24)
	buf[5] = byte(h.Timestamp >> 16)
	buf[6] = byte(h.Timestamp >> 8)
	buf[7] = byte(h.Timestamp)
	buf[8] = byte(h.SSRC >> 24)
	buf[9] = byte(h.SSRC >> 16)
	buf[10] = byte(h.SSRC >> 8)
	buf[11] = byte(h.SSRC)

	for i, csrc := range h.CSRC {
		offset := 12 + i*4
		buf[offset] = byte(csrc >> 24)
		buf[offset+1] = byte(csrc >> 16)
		buf[offset+2] = byte(csrc >> 8)
		buf[offset+3] = byte(csrc)
	}

	return headerSize, nil
}

// DecodeRTPHeader parses RTP header bytes.
func DecodeRTPHeader(buf []byte) (RTPHeader, error) {
	if len(buf) < 12 {
		return RTPHeader{}, fmt.Errorf("rtp header too short: %d", len(buf))
	}
	version := (buf[0] >> 6) & 0x03
	if version != RTPVersion {
		return RTPHeader{}, fmt.Errorf("invalid rtp version %d", version)
	}
	csrcCount := buf[0] & 0x0F
	headerSize := 12 + int(csrcCount)*4
	if len(buf) < headerSize {
		return RTPHeader{}, fmt.Errorf("rtp header csrc too short: got %d need %d", len(buf), headerSize)
	}

	h := RTPHeader{
		Version:        version,
		Padding:        ((buf[0] >> 5) & 0x01) == 1,
		Extension:      ((buf[0] >> 4) & 0x01) == 1,
		CSRCCount:      csrcCount,
		Marker:         ((buf[1] >> 7) & 0x01) == 1,
		PayloadType:    buf[1] & 0x7F,
		SequenceNumber: uint16(buf[2])<<8 | uint16(buf[3]),
		Timestamp:      uint32(buf[4])<<24 | uint32(buf[5])<<16 | uint32(buf[6])<<8 | uint32(buf[7]),
		SSRC:           uint32(buf[8])<<24 | uint32(buf[9])<<16 | uint32(buf[10])<<8 | uint32(buf[11]),
		CSRC:           make([]uint32, int(csrcCount)),
	}
	for i := range h.CSRC {
		offset := 12 + i*4
		h.CSRC[i] = uint32(buf[offset])<<24 | uint32(buf[offset+1])<<16 | uint32(buf[offset+2])<<8 | uint32(buf[offset+3])
	}
	return h, nil
}

// RTPPacket represents a complete RTP packet.
type RTPPacket struct {
	Header  RTPHeader
	Payload []byte
}

// Encode serializes RTP packet bytes.
func (p RTPPacket) Encode() []byte {
	headerSize := p.Header.Size()
	out := make([]byte, headerSize+len(p.Payload))
	_, _ = p.Header.Encode(out)
	copy(out[headerSize:], p.Payload)
	return out
}

// DecodeRTPPacket parses an RTP packet.
func DecodeRTPPacket(buf []byte) (RTPPacket, error) {
	header, err := DecodeRTPHeader(buf)
	if err != nil {
		return RTPPacket{}, err
	}
	headerSize := header.Size()
	if len(buf) < headerSize {
		return RTPPacket{}, fmt.Errorf("rtp packet too short")
	}
	payload := make([]byte, len(buf)-headerSize)
	copy(payload, buf[headerSize:])
	return RTPPacket{Header: header, Payload: payload}, nil
}

// RTPPacketSession tracks packet numbering for an RTP stream.
type RTPPacketSession struct {
	SSRC             uint32
	PayloadType      uint8
	SampleRate       uint32
	SamplesPerPacket uint32
	SequenceNumber   uint16
	Timestamp        uint32
}

// NewRTPPacketSession creates a new RTP packet session.
func NewRTPPacketSession(ssrc uint32, payloadType uint8, sampleRate, samplesPerPacket uint32) *RTPPacketSession {
	return &RTPPacketSession{
		SSRC:             ssrc,
		PayloadType:      payloadType,
		SampleRate:       sampleRate,
		SamplesPerPacket: samplesPerPacket,
	}
}

// CreatePacket wraps payload into RTP and advances sequence/timestamp state.
func (s *RTPPacketSession) CreatePacket(payload []byte, marker bool) RTPPacket {
	header := NewRTPHeader(s.PayloadType, s.SequenceNumber, s.Timestamp, s.SSRC)
	header.Marker = marker
	s.SequenceNumber++
	s.Timestamp += s.SamplesPerPacket
	copied := make([]byte, len(payload))
	copy(copied, payload)
	return RTPPacket{Header: header, Payload: copied}
}

func boolToByte(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}
