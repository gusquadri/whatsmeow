// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"fmt"
	"sort"
)

const (
	RTCPVersion = 2

	RTCPPayloadTypeRTPFB = 205
	RTCPPayloadTypePSFB  = 206

	RTCPFmtNACK = 1
	RTCPFmtPLI  = 1
)

// RTCPHeader is the common header for RTCP packets.
type RTCPHeader struct {
	Version    uint8
	Padding    bool
	CountOrFmt uint8
	PacketType uint8
	Length     uint16
}

// Encode serializes RTCP header bytes.
func (h RTCPHeader) Encode() []byte {
	out := make([]byte, 4)
	out[0] = (h.Version << 6) | (boolToByte(h.Padding) << 5) | (h.CountOrFmt & 0x1F)
	out[1] = h.PacketType
	out[2] = byte(h.Length >> 8)
	out[3] = byte(h.Length)
	return out
}

// DecodeRTCPHeader parses RTCP header bytes.
func DecodeRTCPHeader(data []byte) (RTCPHeader, error) {
	if len(data) < 4 {
		return RTCPHeader{}, fmt.Errorf("rtcp header too short")
	}
	version := (data[0] >> 6) & 0x03
	if version != RTCPVersion {
		return RTCPHeader{}, fmt.Errorf("invalid rtcp version %d", version)
	}
	return RTCPHeader{
		Version:    version,
		Padding:    ((data[0] >> 5) & 0x01) == 1,
		CountOrFmt: data[0] & 0x1F,
		PacketType: data[1],
		Length:     uint16(data[2])<<8 | uint16(data[3]),
	}, nil
}

// RTCPNackEntry encodes PID + BLP for lost packet reporting.
type RTCPNackEntry struct {
	PID uint16
	BLP uint16
}

// LostSequences expands NACK entry into packet sequence numbers.
func (e RTCPNackEntry) LostSequences() []uint16 {
	lost := []uint16{e.PID}
	for i := 0; i < 16; i++ {
		if ((e.BLP >> i) & 0x01) == 1 {
			lost = append(lost, e.PID+uint16(i)+1)
		}
	}
	return lost
}

// RTCPNACK is a Generic NACK (RTPFB/FMT=1) packet.
type RTCPNACK struct {
	SenderSSRC uint32
	MediaSSRC  uint32
	Entries    []RTCPNackEntry
}

// NewRTCPNACK creates a new NACK packet.
func NewRTCPNACK(senderSSRC, mediaSSRC uint32) RTCPNACK {
	return RTCPNACK{SenderSSRC: senderSSRC, MediaSSRC: mediaSSRC}
}

// AddLostSequence appends a lost packet into compact NACK entry form.
func (n *RTCPNACK) AddLostSequence(seq uint16) {
	for i := range n.Entries {
		diff := seq - n.Entries[i].PID
		if diff >= 1 && diff <= 16 {
			n.Entries[i].BLP |= 1 << (diff - 1)
			return
		}
	}
	n.Entries = append(n.Entries, RTCPNackEntry{PID: seq})
}

// AddLostSequences appends multiple lost packets.
func (n *RTCPNACK) AddLostSequences(seqs []uint16) {
	for _, seq := range seqs {
		n.AddLostSequence(seq)
	}
}

// LostSequences flattens all packet IDs referenced by entries.
func (n RTCPNACK) LostSequences() []uint16 {
	all := make([]uint16, 0)
	for _, e := range n.Entries {
		all = append(all, e.LostSequences()...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	uniq := all[:0]
	var prev uint16
	for i, v := range all {
		if i == 0 || v != prev {
			uniq = append(uniq, v)
		}
		prev = v
	}
	return uniq
}

// Encode serializes an RTCP NACK packet.
func (n RTCPNACK) Encode() []byte {
	size := 12 + len(n.Entries)*4
	lengthWords := uint16(size/4 - 1)
	header := RTCPHeader{Version: RTCPVersion, CountOrFmt: RTCPFmtNACK, PacketType: RTCPPayloadTypeRTPFB, Length: lengthWords}
	out := make([]byte, size)
	copy(out[:4], header.Encode())
	out[4] = byte(n.SenderSSRC >> 24)
	out[5] = byte(n.SenderSSRC >> 16)
	out[6] = byte(n.SenderSSRC >> 8)
	out[7] = byte(n.SenderSSRC)
	out[8] = byte(n.MediaSSRC >> 24)
	out[9] = byte(n.MediaSSRC >> 16)
	out[10] = byte(n.MediaSSRC >> 8)
	out[11] = byte(n.MediaSSRC)
	for i, entry := range n.Entries {
		offset := 12 + i*4
		out[offset] = byte(entry.PID >> 8)
		out[offset+1] = byte(entry.PID)
		out[offset+2] = byte(entry.BLP >> 8)
		out[offset+3] = byte(entry.BLP)
	}
	return out
}

// DecodeRTCPNACK parses RTCP Generic NACK packets.
func DecodeRTCPNACK(data []byte) (RTCPNACK, error) {
	header, err := DecodeRTCPHeader(data)
	if err != nil {
		return RTCPNACK{}, err
	}
	if header.PacketType != RTCPPayloadTypeRTPFB || header.CountOrFmt != RTCPFmtNACK {
		return RTCPNACK{}, fmt.Errorf("not a generic nack packet")
	}
	if len(data) < 12 {
		return RTCPNACK{}, fmt.Errorf("nack packet too short")
	}
	n := RTCPNACK{
		SenderSSRC: uint32(data[4])<<24 | uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7]),
		MediaSSRC:  uint32(data[8])<<24 | uint32(data[9])<<16 | uint32(data[10])<<8 | uint32(data[11]),
	}
	for offset := 12; offset+3 < len(data); offset += 4 {
		n.Entries = append(n.Entries, RTCPNackEntry{PID: uint16(data[offset])<<8 | uint16(data[offset+1]), BLP: uint16(data[offset+2])<<8 | uint16(data[offset+3])})
	}
	return n, nil
}

// RTCPPLI is a payload-specific picture loss indication packet.
type RTCPPLI struct {
	SenderSSRC uint32
	MediaSSRC  uint32
}

// Encode serializes a PLI packet.
func (p RTCPPLI) Encode() []byte {
	header := RTCPHeader{Version: RTCPVersion, CountOrFmt: RTCPFmtPLI, PacketType: RTCPPayloadTypePSFB, Length: 2}
	out := make([]byte, 12)
	copy(out[:4], header.Encode())
	out[4] = byte(p.SenderSSRC >> 24)
	out[5] = byte(p.SenderSSRC >> 16)
	out[6] = byte(p.SenderSSRC >> 8)
	out[7] = byte(p.SenderSSRC)
	out[8] = byte(p.MediaSSRC >> 24)
	out[9] = byte(p.MediaSSRC >> 16)
	out[10] = byte(p.MediaSSRC >> 8)
	out[11] = byte(p.MediaSSRC)
	return out
}

// NackStats tracks NACK generation state.
type NackStats struct {
	MissingDetected uint64
	NackBatches     uint64
}

// NackTracker tracks missing RTP sequence numbers and yields periodic NACKs.
type NackTracker struct {
	lastSeq     *uint16
	missing     map[uint16]uint8
	maxAttempts uint8
	maxTracked  int
	stats       NackStats
}

// NewNackTracker creates a NACK tracker.
func NewNackTracker(maxTracked int, maxAttempts uint8) *NackTracker {
	if maxTracked <= 0 {
		maxTracked = 256
	}
	if maxAttempts == 0 {
		maxAttempts = 8
	}
	return &NackTracker{missing: make(map[uint16]uint8), maxTracked: maxTracked, maxAttempts: maxAttempts}
}

// OnPacketReceived records incoming sequence and returns newly detected missing packets.
func (n *NackTracker) OnPacketReceived(seq uint16) []uint16 {
	if n.lastSeq == nil {
		n.lastSeq = &seq
		return nil
	}
	last := *n.lastSeq
	if seq == last {
		return nil
	}

	if seq > last+1 {
		newMissing := make([]uint16, 0, int(seq-last-1))
		for s := last + 1; s < seq; s++ {
			if len(n.missing) >= n.maxTracked {
				break
			}
			n.missing[s] = 0
			newMissing = append(newMissing, s)
		}
		n.stats.MissingDetected += uint64(len(newMissing))
		delete(n.missing, seq)
		n.lastSeq = &seq
		return newMissing
	}

	delete(n.missing, seq)
	if seq > last {
		n.lastSeq = &seq
	}
	return nil
}

// GetPendingNACKs returns missing packets to request again.
func (n *NackTracker) GetPendingNACKs(max int) []uint16 {
	if max <= 0 {
		max = 32
	}
	seqs := make([]uint16, 0, len(n.missing))
	for seq := range n.missing {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	out := make([]uint16, 0, max)
	for _, seq := range seqs {
		attempts := n.missing[seq]
		if attempts >= n.maxAttempts {
			delete(n.missing, seq)
			continue
		}
		n.missing[seq] = attempts + 1
		out = append(out, seq)
		if len(out) >= max {
			break
		}
	}
	if len(out) > 0 {
		n.stats.NackBatches++
	}
	return out
}

// Stats returns current tracker stats.
func (n *NackTracker) Stats() NackStats {
	return n.stats
}

// RetransmitBuffer stores recent RTP packets for retransmission by sequence.
type RetransmitBuffer struct {
	maxEntries int
	order      []uint16
	packets    map[uint16][]byte
}

// NewRetransmitBuffer creates a retransmit buffer.
func NewRetransmitBuffer(maxEntries int) *RetransmitBuffer {
	if maxEntries <= 0 {
		maxEntries = 512
	}
	return &RetransmitBuffer{maxEntries: maxEntries, packets: make(map[uint16][]byte)}
}

// Store saves encoded RTP packet bytes by sequence number.
func (b *RetransmitBuffer) Store(seq uint16, packet []byte) {
	copied := make([]byte, len(packet))
	copy(copied, packet)
	if _, exists := b.packets[seq]; !exists {
		b.order = append(b.order, seq)
	}
	b.packets[seq] = copied
	for len(b.order) > b.maxEntries {
		oldest := b.order[0]
		b.order = b.order[1:]
		delete(b.packets, oldest)
	}
}

// Get returns stored packet bytes for sequence number.
func (b *RetransmitBuffer) Get(seq uint16) ([]byte, bool) {
	pkt, ok := b.packets[seq]
	if !ok {
		return nil, false
	}
	copied := make([]byte, len(pkt))
	copy(copied, pkt)
	return copied, true
}
