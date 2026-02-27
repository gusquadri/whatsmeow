// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"

	"go.mau.fi/whatsmeow/types"
)

var (
	// ErrNoAudioSource indicates no configured audio capture source.
	ErrNoAudioSource = errors.New("no audio frame source configured")
	// ErrNoVideoSource indicates no configured video capture source.
	ErrNoVideoSource = errors.New("no video frame source configured")
)

// CallMediaFramePacketizer can translate raw frame bytes into transport payloads.
type CallMediaFramePacketizer interface {
	BuildOutgoingAudioPayload(callID string, frame []byte) ([]byte, error)
	BuildOutgoingVideoPayload(callID string, frame []byte) ([]byte, error)
}

// CallMediaFeedbackProvider surfaces generated RTCP/control payloads.
type CallMediaFeedbackProvider interface {
	DrainOutgoingControl(callID string) [][]byte
}

// CallMediaFrameSourceProvider exposes configured outgoing frame sources.
type CallMediaFrameSourceProvider interface {
	ReadOutgoingAudioFrame(ctx context.Context, callID string) ([]byte, error)
	ReadOutgoingVideoFrame(ctx context.Context, callID string) ([]byte, error)
}

// RTPCallMediaEngineConfig configures RTPCallMediaEngine.
type RTPCallMediaEngineConfig struct {
	AudioPayloadType  uint8
	VideoPayloadType  uint8
	AudioSampleRate   uint32
	AudioFrameSamples uint32
	JitterConfig      JitterBufferConfig
	NackMaxBatch      int
	RetransmitBuffer  int
	SSRC              uint32
}

// DefaultRTPCallMediaEngineConfig returns default configuration values.
func DefaultRTPCallMediaEngineConfig() RTPCallMediaEngineConfig {
	return RTPCallMediaEngineConfig{
		AudioPayloadType:  RTPPayloadTypeOpus,
		VideoPayloadType:  121,
		AudioSampleRate:   16000,
		AudioFrameSamples: 320,
		JitterConfig:      DefaultJitterBufferConfig(),
		NackMaxBatch:      32,
		RetransmitBuffer:  512,
	}
}

type rtpCallMediaSession struct {
	mu sync.Mutex

	srtp       *SRTPSession
	audioOut   *RTPPacketSession
	videoOut   *RTPPacketSession
	jitter     *JitterBuffer
	nack       *NackTracker
	retransmit *RetransmitBuffer
	mediaIO    CallMediaIO
	localSSRC  uint32
	feedback   [][]byte
}

// RTPCallMediaEngine is a concrete call media engine that handles RTP/SRTP,
// RTCP feedback, jitter buffering and codec IO hooks.
type RTPCallMediaEngine struct {
	cfg        RTPCallMediaEngineConfig
	audioCodec CallAudioCodec
	videoCodec CallVideoCodec

	mu       sync.RWMutex
	mediaIO  CallMediaIO
	sessions map[string]*rtpCallMediaSession
}

// NewRTPCallMediaEngine creates a RTP/SRTP media engine.
func NewRTPCallMediaEngine(cfg RTPCallMediaEngineConfig, audioCodec CallAudioCodec, videoCodec CallVideoCodec, mediaIO CallMediaIO) *RTPCallMediaEngine {
	if cfg.AudioPayloadType == 0 {
		cfg.AudioPayloadType = RTPPayloadTypeOpus
	}
	if cfg.VideoPayloadType == 0 {
		cfg.VideoPayloadType = 121
	}
	if cfg.AudioSampleRate == 0 {
		cfg.AudioSampleRate = 16000
	}
	if cfg.AudioFrameSamples == 0 {
		cfg.AudioFrameSamples = 320
	}
	if cfg.NackMaxBatch <= 0 {
		cfg.NackMaxBatch = 32
	}
	if cfg.RetransmitBuffer <= 0 {
		cfg.RetransmitBuffer = 512
	}
	if audioCodec == nil {
		audioCodec = OpusPacketCodec{}
	}
	if videoCodec == nil {
		videoCodec = PassThroughVideoCodec{}
	}
	if cfg.JitterConfig.SampleRate == 0 {
		cfg.JitterConfig = DefaultJitterBufferConfig()
	}
	return &RTPCallMediaEngine{
		cfg:        cfg,
		audioCodec: audioCodec,
		videoCodec: videoCodec,
		mediaIO:    mediaIO,
		sessions:   make(map[string]*rtpCallMediaSession),
	}
}

func (e *RTPCallMediaEngine) SetMediaIO(io CallMediaIO) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mediaIO = io
	for _, session := range e.sessions {
		session.mu.Lock()
		session.mediaIO = io
		session.mu.Unlock()
	}
}

func (e *RTPCallMediaEngine) Start(_ context.Context, info *types.CallInfo, keys *DerivedCallKeys) error {
	if info == nil || info.CallID == "" {
		return fmt.Errorf("call info is nil or call id is empty")
	}
	if keys == nil {
		return fmt.Errorf("derived call keys are required")
	}
	localSSRC, err := e.pickSSRC()
	if err != nil {
		return err
	}
	// WA Web relay media currently uses the same HBH SRTP keying material in both
	// directions for this data path, so both local and remote inputs are identical.
	session, err := NewSRTPSession(keys.HBHSRTP, keys.HBHSRTP)
	if err != nil {
		return err
	}

	jcfg := e.cfg.JitterConfig
	if jcfg.SampleRate == 0 {
		jcfg.SampleRate = e.cfg.AudioSampleRate
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.sessions[info.CallID] = &rtpCallMediaSession{
		srtp:       session,
		audioOut:   NewRTPPacketSession(localSSRC, e.cfg.AudioPayloadType, e.cfg.AudioSampleRate, e.cfg.AudioFrameSamples),
		videoOut:   NewRTPPacketSession(localSSRC+1, e.cfg.VideoPayloadType, 90000, 3000),
		jitter:     NewJitterBuffer(jcfg),
		nack:       NewNackTracker(512, 8),
		retransmit: NewRetransmitBuffer(e.cfg.RetransmitBuffer),
		mediaIO:    e.mediaIO,
		localSSRC:  localSSRC,
	}
	return nil
}

func (e *RTPCallMediaEngine) Stop(_ context.Context, info *types.CallInfo) error {
	if info == nil || info.CallID == "" {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.sessions, info.CallID)
	return nil
}

func (e *RTPCallMediaEngine) HandleIncomingPayload(ctx context.Context, info *types.CallInfo, payload []byte) error {
	if info == nil || info.CallID == "" {
		return fmt.Errorf("call info is nil or call id is empty")
	}
	session := e.getSession(info.CallID)
	if session == nil {
		return fmt.Errorf("call %s media session not active", info.CallID)
	}
	if len(payload) == 0 {
		return nil
	}

	if isRTCPPayload(payload) {
		return e.handleIncomingRTCP(session, payload)
	}
	packet, err := session.srtp.Unprotect(payload)
	if err != nil {
		return err
	}

	session.mu.Lock()
	missing := session.nack.OnPacketReceived(packet.Header.SequenceNumber)
	if len(missing) > 0 {
		nack := NewRTCPNACK(session.localSSRC, packet.Header.SSRC)
		nack.AddLostSequences(missing)
		session.feedback = append(session.feedback, nack.Encode())
	}
	session.mu.Unlock()

	if packet.Header.PayloadType == e.cfg.AudioPayloadType {
		session.mu.Lock()
		session.jitter.Push(packet)
		session.mu.Unlock()
		for {
			session.mu.Lock()
			next := session.jitter.Pop()
			ioCfg := session.mediaIO
			session.mu.Unlock()
			if next == nil {
				break
			}
			decoded, decErr := e.audioCodec.Decode(info.CallID, next.Payload)
			if decErr != nil {
				return decErr
			}
			if ioCfg.AudioSink != nil {
				if sinkErr := ioCfg.AudioSink.HandleAudioFrame(ctx, info.CallID, decoded); sinkErr != nil {
					return sinkErr
				}
			}
		}
		return nil
	}

	decoded, decErr := e.videoCodec.Decode(info.CallID, packet.Payload)
	if decErr != nil {
		return decErr
	}
	session.mu.Lock()
	ioCfg := session.mediaIO
	session.mu.Unlock()
	if ioCfg.VideoSink != nil {
		return ioCfg.VideoSink.HandleVideoFrame(ctx, info.CallID, decoded)
	}
	return nil
}

func (e *RTPCallMediaEngine) handleIncomingRTCP(session *rtpCallMediaSession, payload []byte) error {
	header, err := DecodeRTCPHeader(payload)
	if err != nil {
		return err
	}
	if header.PacketType != RTCPPayloadTypeRTPFB || header.CountOrFmt != RTCPFmtNACK {
		return nil
	}
	nack, err := DecodeRTCPNACK(payload)
	if err != nil {
		return err
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	for _, seq := range nack.LostSequences() {
		if pkt, ok := session.retransmit.Get(seq); ok {
			session.feedback = append(session.feedback, pkt)
		}
	}
	return nil
}

// BuildOutgoingAudioPayload packetizes+encrypts an outgoing audio frame.
func (e *RTPCallMediaEngine) BuildOutgoingAudioPayload(callID string, frame []byte) ([]byte, error) {
	session := e.getSession(callID)
	if session == nil {
		return nil, fmt.Errorf("call %s media session not active", callID)
	}
	encoded, err := e.audioCodec.Encode(callID, frame)
	if err != nil {
		return nil, err
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	rtp := session.audioOut.CreatePacket(encoded, false)
	encrypted, err := session.srtp.Protect(rtp)
	if err != nil {
		return nil, err
	}
	session.retransmit.Store(rtp.Header.SequenceNumber, encrypted)
	return encrypted, nil
}

// BuildOutgoingVideoPayload packetizes+encrypts an outgoing video frame.
func (e *RTPCallMediaEngine) BuildOutgoingVideoPayload(callID string, frame []byte) ([]byte, error) {
	session := e.getSession(callID)
	if session == nil {
		return nil, fmt.Errorf("call %s media session not active", callID)
	}
	encoded, err := e.videoCodec.Encode(callID, frame)
	if err != nil {
		return nil, err
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	rtp := session.videoOut.CreatePacket(encoded, true)
	encrypted, err := session.srtp.Protect(rtp)
	if err != nil {
		return nil, err
	}
	session.retransmit.Store(rtp.Header.SequenceNumber, encrypted)
	return encrypted, nil
}

// DrainOutgoingControl returns pending control/retransmit packets.
func (e *RTPCallMediaEngine) DrainOutgoingControl(callID string) [][]byte {
	session := e.getSession(callID)
	if session == nil {
		return nil
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	out := make([][]byte, len(session.feedback))
	for i, payload := range session.feedback {
		copied := make([]byte, len(payload))
		copy(copied, payload)
		out[i] = copied
	}
	session.feedback = session.feedback[:0]
	return out
}

// ReadOutgoingAudioFrame reads a frame from configured audio source.
func (e *RTPCallMediaEngine) ReadOutgoingAudioFrame(ctx context.Context, callID string) ([]byte, error) {
	session := e.getSession(callID)
	if session == nil {
		return nil, fmt.Errorf("call %s media session not active", callID)
	}
	session.mu.Lock()
	source := session.mediaIO.AudioSource
	session.mu.Unlock()
	if source == nil {
		return nil, ErrNoAudioSource
	}
	return source.ReadAudioFrame(ctx, callID)
}

// ReadOutgoingVideoFrame reads a frame from configured video source.
func (e *RTPCallMediaEngine) ReadOutgoingVideoFrame(ctx context.Context, callID string) ([]byte, error) {
	session := e.getSession(callID)
	if session == nil {
		return nil, fmt.Errorf("call %s media session not active", callID)
	}
	session.mu.Lock()
	source := session.mediaIO.VideoSource
	session.mu.Unlock()
	if source == nil {
		return nil, ErrNoVideoSource
	}
	return source.ReadVideoFrame(ctx, callID)
}

func (e *RTPCallMediaEngine) pickSSRC() (uint32, error) {
	if e.cfg.SSRC != 0 {
		return e.cfg.SSRC, nil
	}
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("failed to generate ssrc: %w", err)
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), nil
}

func (e *RTPCallMediaEngine) getSession(callID string) *rtpCallMediaSession {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.sessions[callID]
}

func isRTCPPayload(payload []byte) bool {
	if len(payload) < 2 {
		return false
	}
	if (payload[0]>>6)&0x03 != RTCPVersion {
		return false
	}
	pt := payload[1]
	return pt >= 200 && pt <= 223
}
