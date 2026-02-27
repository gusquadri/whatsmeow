// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"sort"
	"time"
)

// JitterBufferConfig configures RTP jitter buffering behavior.
type JitterBufferConfig struct {
	TargetDelay time.Duration
	MaxPackets  int
	MaxAge      time.Duration
	SampleRate  uint32
}

// DefaultJitterBufferConfig returns call-appropriate defaults.
func DefaultJitterBufferConfig() JitterBufferConfig {
	return JitterBufferConfig{
		TargetDelay: 60 * time.Millisecond,
		MaxPackets:  50,
		MaxAge:      500 * time.Millisecond,
		SampleRate:  16000,
	}
}

// JitterBufferStats captures reorder/drop/jitter metrics.
type JitterBufferStats struct {
	PacketsReceived  uint64
	PacketsPlayed    uint64
	PacketsDropped   uint64
	PacketsDuplicate uint64
	PacketsReordered uint64
	JitterMS         float64
	BufferDepth      int
}

type jitterBufferedPacket struct {
	packet     RTPPacket
	receivedAt time.Time
}

// JitterBuffer smooths network jitter for RTP playout.
type JitterBuffer struct {
	cfg             JitterBufferConfig
	buffer          map[uint16]jitterBufferedPacket
	nextSeq         *uint16
	firstPacketTime *time.Time
	lastArrival     *time.Time
	lastTimestamp   *uint32
	jitterEstimate  float64
	stats           JitterBufferStats
}

// NewJitterBuffer creates a jitter buffer.
func NewJitterBuffer(cfg JitterBufferConfig) *JitterBuffer {
	if cfg.MaxPackets <= 0 {
		cfg.MaxPackets = 50
	}
	if cfg.SampleRate == 0 {
		cfg.SampleRate = 16000
	}
	if cfg.TargetDelay < 0 {
		cfg.TargetDelay = 60 * time.Millisecond
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 500 * time.Millisecond
	}
	return &JitterBuffer{cfg: cfg, buffer: make(map[uint16]jitterBufferedPacket)}
}

// Push inserts an incoming RTP packet.
func (j *JitterBuffer) Push(packet RTPPacket) {
	now := time.Now()
	seq := packet.Header.SequenceNumber
	j.stats.PacketsReceived++
	if j.firstPacketTime == nil {
		j.firstPacketTime = &now
		j.nextSeq = &seq
	}
	j.updateJitter(now, packet.Header.Timestamp)

	if _, exists := j.buffer[seq]; exists {
		j.stats.PacketsDuplicate++
		return
	}
	if j.stats.PacketsPlayed > 0 && j.nextSeq != nil {
		diff := seqDiffSigned(seq, *j.nextSeq)
		if diff < 0 && diff > -1000 {
			j.stats.PacketsDropped++
			return
		}
		if diff < 0 {
			j.stats.PacketsReordered++
		}
	}
	if len(j.buffer) >= j.cfg.MaxPackets {
		oldest := j.sortedSeqs()[0]
		delete(j.buffer, oldest)
		j.stats.PacketsDropped++
	}
	j.buffer[seq] = jitterBufferedPacket{packet: packet, receivedAt: now}
	j.stats.BufferDepth = len(j.buffer)
}

// Pop returns the next packet ready for playout.
func (j *JitterBuffer) Pop() *RTPPacket {
	now := time.Now()
	j.cleanupExpired(now)
	if j.firstPacketTime == nil {
		return nil
	}
	if now.Sub(*j.firstPacketTime) < j.cfg.TargetDelay {
		return nil
	}
	if len(j.buffer) == 0 || j.nextSeq == nil {
		return nil
	}

	if j.stats.PacketsPlayed == 0 {
		minSeq := j.sortedSeqs()[0]
		j.nextSeq = &minSeq
	}

	if buffered, ok := j.buffer[*j.nextSeq]; ok {
		delete(j.buffer, *j.nextSeq)
		next := *j.nextSeq + 1
		j.nextSeq = &next
		j.stats.PacketsPlayed++
		j.stats.BufferDepth = len(j.buffer)
		pkt := buffered.packet
		return &pkt
	}

	seqs := j.sortedSeqs()
	if len(seqs) == 0 {
		return nil
	}
	available := seqs[0]
	gap := int(seqDistanceForward(*j.nextSeq, available))
	if gap >= 0 && gap < 100 {
		j.stats.PacketsDropped += uint64(gap)
		j.nextSeq = &available
		if buffered, ok := j.buffer[available]; ok {
			delete(j.buffer, available)
			next := available + 1
			j.nextSeq = &next
			j.stats.PacketsPlayed++
			j.stats.BufferDepth = len(j.buffer)
			pkt := buffered.packet
			return &pkt
		}
	}
	return nil
}

func (j *JitterBuffer) updateJitter(arrival time.Time, ts uint32) {
	if j.lastArrival != nil && j.lastTimestamp != nil {
		arrivalDiffUS := float64(arrival.Sub(*j.lastArrival).Microseconds())
		tsDiff := float64(ts - *j.lastTimestamp)
		expectedDiffUS := (tsDiff / float64(j.cfg.SampleRate)) * 1_000_000.0
		d := absFloat64(arrivalDiffUS - expectedDiffUS)
		j.jitterEstimate += (d - j.jitterEstimate) / 16.0
		j.stats.JitterMS = j.jitterEstimate / 1000.0
	}
	j.lastArrival = &arrival
	j.lastTimestamp = &ts
}

func (j *JitterBuffer) cleanupExpired(now time.Time) {
	for seq, buffered := range j.buffer {
		if now.Sub(buffered.receivedAt) > j.cfg.MaxAge {
			delete(j.buffer, seq)
			j.stats.PacketsDropped++
		}
	}
	j.stats.BufferDepth = len(j.buffer)
}

func (j *JitterBuffer) sortedSeqs() []uint16 {
	seqs := make([]uint16, 0, len(j.buffer))
	for seq := range j.buffer {
		seqs = append(seqs, seq)
	}
	if j.nextSeq != nil && j.stats.PacketsPlayed > 0 {
		base := *j.nextSeq
		sort.Slice(seqs, func(i, k int) bool {
			di := seqDistanceForward(base, seqs[i])
			dk := seqDistanceForward(base, seqs[k])
			if di == dk {
				return seqs[i] < seqs[k]
			}
			return di < dk
		})
		return seqs
	}
	sort.Slice(seqs, func(i, k int) bool { return seqs[i] < seqs[k] })
	return seqs
}

func seqDistanceForward(from, to uint16) uint16 {
	return to - from
}

func seqDiffSigned(a, b uint16) int {
	return int(int16(a - b))
}

// Stats returns jitter buffer stats snapshot.
func (j *JitterBuffer) Stats() JitterBufferStats {
	return j.stats
}

func absFloat64(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}
