// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"fmt"
)

const (
	SRTPAuthTagLen = 10

	srtpLabelRTPEncryption = 0x00
	srtpLabelRTPAuth       = 0x01
	srtpLabelRTPSalt       = 0x02
)

// SRTPCryptoContext handles one-direction SRTP packet protection.
type SRTPCryptoContext struct {
	sessionKey  [16]byte
	sessionSalt [14]byte
	authKey     [20]byte

	roc         uint32
	lastSeq     uint16
	initialized bool
}

// NewSRTPCryptoContext constructs a SRTP context from RFC3711 keying material.
func NewSRTPCryptoContext(keying SRTPKeyingMaterial) (*SRTPCryptoContext, error) {
	sessionKey, err := deriveSRTPKey(keying.MasterKey, keying.MasterSalt, srtpLabelRTPEncryption, 16)
	if err != nil {
		return nil, err
	}
	authKey, err := deriveSRTPKey(keying.MasterKey, keying.MasterSalt, srtpLabelRTPAuth, 20)
	if err != nil {
		return nil, err
	}
	sessionSalt, err := deriveSRTPKey(keying.MasterKey, keying.MasterSalt, srtpLabelRTPSalt, 14)
	if err != nil {
		return nil, err
	}

	ctx := &SRTPCryptoContext{}
	copy(ctx.sessionKey[:], sessionKey)
	copy(ctx.authKey[:], authKey)
	copy(ctx.sessionSalt[:], sessionSalt)
	return ctx, nil
}

func deriveSRTPKey(masterKey [16]byte, masterSalt [14]byte, label byte, outLen int) ([]byte, error) {
	x := make([]byte, 16)
	copy(x[:14], masterSalt[:])
	x[7] ^= label

	block, err := aes.NewCipher(masterKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create aes cipher: %w", err)
	}
	stream := cipher.NewCTR(block, x)
	out := make([]byte, outLen)
	stream.XORKeyStream(out, out)
	return out, nil
}

func (ctx *SRTPCryptoContext) updateROC(seq uint16) {
	if !ctx.initialized {
		ctx.lastSeq = seq
		ctx.initialized = true
		return
	}
	diff := int32(seq) - int32(ctx.lastSeq)
	if diff < -32768 {
		ctx.roc++
	}
	ctx.lastSeq = seq
}

func (ctx *SRTPCryptoContext) packetIndex(seq uint16) uint64 {
	return (uint64(ctx.roc) << 16) | uint64(seq)
}

func (ctx *SRTPCryptoContext) generateIV(ssrc uint32, index uint64) [16]byte {
	var iv [16]byte
	copy(iv[:14], ctx.sessionSalt[:])
	ssrcBytes := []byte{byte(ssrc >> 24), byte(ssrc >> 16), byte(ssrc >> 8), byte(ssrc)}
	for i := 0; i < 4; i++ {
		iv[4+i] ^= ssrcBytes[i]
	}
	idxBytes := []byte{
		byte(index >> 40),
		byte(index >> 32),
		byte(index >> 24),
		byte(index >> 16),
		byte(index >> 8),
		byte(index),
	}
	for i := 0; i < 6; i++ {
		iv[8+i] ^= idxBytes[i]
	}
	return iv
}

func (ctx *SRTPCryptoContext) computeAuthTag(data []byte, roc uint32) [SRTPAuthTagLen]byte {
	mac := hmac.New(sha1.New, ctx.authKey[:])
	_, _ = mac.Write(data)
	_, _ = mac.Write([]byte{byte(roc >> 24), byte(roc >> 16), byte(roc >> 8), byte(roc)})
	sum := mac.Sum(nil)
	var tag [SRTPAuthTagLen]byte
	copy(tag[:], sum[:SRTPAuthTagLen])
	return tag
}

// Protect encrypts an RTP packet into SRTP bytes.
func (ctx *SRTPCryptoContext) Protect(packet RTPPacket) ([]byte, error) {
	ctx.updateROC(packet.Header.SequenceNumber)
	index := ctx.packetIndex(packet.Header.SequenceNumber)

	headerSize := packet.Header.Size()
	out := make([]byte, headerSize+len(packet.Payload)+SRTPAuthTagLen)
	if _, err := packet.Header.Encode(out[:headerSize]); err != nil {
		return nil, err
	}
	copy(out[headerSize:headerSize+len(packet.Payload)], packet.Payload)

	iv := ctx.generateIV(packet.Header.SSRC, index)
	block, err := aes.NewCipher(ctx.sessionKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create aes cipher: %w", err)
	}
	stream := cipher.NewCTR(block, iv[:])
	stream.XORKeyStream(out[headerSize:headerSize+len(packet.Payload)], out[headerSize:headerSize+len(packet.Payload)])

	authPortionLen := headerSize + len(packet.Payload)
	tag := ctx.computeAuthTag(out[:authPortionLen], ctx.roc)
	copy(out[authPortionLen:], tag[:])
	return out, nil
}

// Unprotect decrypts SRTP bytes into an RTP packet.
func (ctx *SRTPCryptoContext) Unprotect(data []byte) (RTPPacket, error) {
	if len(data) < 12+SRTPAuthTagLen {
		return RTPPacket{}, fmt.Errorf("srtp packet too short: %d", len(data))
	}

	header, err := DecodeRTPHeader(data)
	if err != nil {
		return RTPPacket{}, err
	}
	headerSize := header.Size()
	if len(data) < headerSize+SRTPAuthTagLen {
		return RTPPacket{}, fmt.Errorf("invalid srtp packet size")
	}

	ctx.updateROC(header.SequenceNumber)
	index := ctx.packetIndex(header.SequenceNumber)

	authPortion := data[:len(data)-SRTPAuthTagLen]
	receivedTag := data[len(data)-SRTPAuthTagLen:]
	computedTag := ctx.computeAuthTag(authPortion, ctx.roc)
	if subtle.ConstantTimeCompare(receivedTag, computedTag[:]) != 1 {
		return RTPPacket{}, fmt.Errorf("srtp authentication failed")
	}

	payload := make([]byte, len(data)-headerSize-SRTPAuthTagLen)
	copy(payload, data[headerSize:len(data)-SRTPAuthTagLen])

	iv := ctx.generateIV(header.SSRC, index)
	block, err := aes.NewCipher(ctx.sessionKey[:])
	if err != nil {
		return RTPPacket{}, fmt.Errorf("failed to create aes cipher: %w", err)
	}
	stream := cipher.NewCTR(block, iv[:])
	stream.XORKeyStream(payload, payload)
	return RTPPacket{Header: header, Payload: payload}, nil
}

// SRTPSession has separate send/receive contexts.
type SRTPSession struct {
	Send *SRTPCryptoContext
	Recv *SRTPCryptoContext
}

// NewSRTPSession creates a SRTP session with send and receive keying material.
func NewSRTPSession(send, recv SRTPKeyingMaterial) (*SRTPSession, error) {
	sendCtx, err := NewSRTPCryptoContext(send)
	if err != nil {
		return nil, err
	}
	recvCtx, err := NewSRTPCryptoContext(recv)
	if err != nil {
		return nil, err
	}
	return &SRTPSession{Send: sendCtx, Recv: recvCtx}, nil
}

// Protect encrypts an outgoing packet.
func (s *SRTPSession) Protect(packet RTPPacket) ([]byte, error) {
	return s.Send.Protect(packet)
}

// Unprotect decrypts an incoming packet.
func (s *SRTPSession) Unprotect(data []byte) (RTPPacket, error) {
	return s.Recv.Unprotect(data)
}
