// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
)

// VoIPStreamLayer matches callsreferences/waproto/voip.proto stream layer values.
type VoIPStreamLayer uint32

const (
	StreamLayerAudio               VoIPStreamLayer = 0
	StreamLayerVideoStream0        VoIPStreamLayer = 1
	StreamLayerVideoStream1        VoIPStreamLayer = 2
	StreamLayerHBHFECClientToRelay VoIPStreamLayer = 3
	StreamLayerHBHFECRelayToClient VoIPStreamLayer = 4
	StreamLayerAppDataStream0      VoIPStreamLayer = 5
	StreamLayerTranscriptionStream VoIPStreamLayer = 6
)

// VoIPPayloadType matches callsreferences/waproto/voip.proto payload types.
type VoIPPayloadType uint32

const (
	PayloadTypeMedia   VoIPPayloadType = 0
	PayloadTypeFEC     VoIPPayloadType = 1
	PayloadTypeNACK    VoIPPayloadType = 2
	PayloadTypeAppData VoIPPayloadType = 3
	PayloadTypeHBHFEC  VoIPPayloadType = 4
)

// SenderSubscription encodes one sender stream subscription entry.
type SenderSubscription struct {
	SenderJID   string
	PID         *uint32
	SSRC        *uint32
	SSRCs       []uint32
	StreamLayer *VoIPStreamLayer
	PayloadType *VoIPPayloadType
}

// SenderSubscriptions is the container message for STUN 0x4000 attribute.
type SenderSubscriptions struct {
	Senders []SenderSubscription
}

// BuildAudioSenderSubscriptions returns encoded protobuf bytes for a minimal
// audio sender subscription.
func BuildAudioSenderSubscriptions(ssrc uint32) []byte {
	layer := StreamLayerAudio
	ptype := PayloadTypeMedia
	value := SenderSubscriptions{Senders: []SenderSubscription{{SSRC: &ssrc, StreamLayer: &layer, PayloadType: &ptype}}}
	return value.Encode()
}

// BuildAudioSenderSubscriptionsWithJID returns encoded protobuf bytes for a
// sender subscription with sender JID.
func BuildAudioSenderSubscriptionsWithJID(ssrc uint32, senderJID string) []byte {
	layer := StreamLayerAudio
	ptype := PayloadTypeMedia
	value := SenderSubscriptions{Senders: []SenderSubscription{{SenderJID: senderJID, SSRC: &ssrc, StreamLayer: &layer, PayloadType: &ptype}}}
	return value.Encode()
}

// Encode marshals SenderSubscriptions as protobuf wire bytes.
func (s SenderSubscriptions) Encode() []byte {
	out := make([]byte, 0)
	for _, sender := range s.Senders {
		senderBytes := encodeSenderSubscription(sender)
		out = protowire.AppendTag(out, 1, protowire.BytesType)
		out = protowire.AppendBytes(out, senderBytes)
	}
	return out
}

func encodeSenderSubscription(sender SenderSubscription) []byte {
	msg := make([]byte, 0)
	if sender.SenderJID != "" {
		msg = protowire.AppendTag(msg, 1, protowire.BytesType)
		msg = protowire.AppendString(msg, sender.SenderJID)
	}
	if sender.PID != nil {
		msg = protowire.AppendTag(msg, 2, protowire.VarintType)
		msg = protowire.AppendVarint(msg, uint64(*sender.PID))
	}
	if sender.SSRC != nil {
		msg = protowire.AppendTag(msg, 3, protowire.VarintType)
		msg = protowire.AppendVarint(msg, uint64(*sender.SSRC))
	}
	for _, ssrc := range sender.SSRCs {
		msg = protowire.AppendTag(msg, 4, protowire.VarintType)
		msg = protowire.AppendVarint(msg, uint64(ssrc))
	}
	if sender.StreamLayer != nil {
		msg = protowire.AppendTag(msg, 5, protowire.VarintType)
		msg = protowire.AppendVarint(msg, uint64(*sender.StreamLayer))
	}
	if sender.PayloadType != nil {
		msg = protowire.AppendTag(msg, 6, protowire.VarintType)
		msg = protowire.AppendVarint(msg, uint64(*sender.PayloadType))
	}
	return msg
}

// DecodeSenderSubscriptions parses protobuf wire bytes into SenderSubscriptions.
func DecodeSenderSubscriptions(data []byte) (SenderSubscriptions, error) {
	result := SenderSubscriptions{}
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return SenderSubscriptions{}, fmt.Errorf("invalid sender-subscriptions tag")
		}
		data = data[n:]
		if num != 1 || typ != protowire.BytesType {
			skip, err := consumeUnknownWireValue(data, typ)
			if err != nil {
				return SenderSubscriptions{}, err
			}
			data = data[skip:]
			continue
		}
		body, m := protowire.ConsumeBytes(data)
		if m < 0 {
			return SenderSubscriptions{}, fmt.Errorf("invalid sender payload")
		}
		data = data[m:]
		sender, err := decodeSenderSubscription(body)
		if err != nil {
			return SenderSubscriptions{}, err
		}
		result.Senders = append(result.Senders, sender)
	}
	return result, nil
}

func decodeSenderSubscription(data []byte) (SenderSubscription, error) {
	var out SenderSubscription
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return SenderSubscription{}, fmt.Errorf("invalid sender tag")
		}
		data = data[n:]
		switch num {
		case 1:
			if typ != protowire.BytesType {
				return SenderSubscription{}, fmt.Errorf("invalid sender_jid wire type")
			}
			v, m := protowire.ConsumeString(data)
			if m < 0 {
				return SenderSubscription{}, fmt.Errorf("invalid sender_jid")
			}
			out.SenderJID = v
			data = data[m:]
		case 2:
			v, m := protowire.ConsumeVarint(data)
			if m < 0 {
				return SenderSubscription{}, fmt.Errorf("invalid pid")
			}
			pid := uint32(v)
			out.PID = &pid
			data = data[m:]
		case 3:
			v, m := protowire.ConsumeVarint(data)
			if m < 0 {
				return SenderSubscription{}, fmt.Errorf("invalid ssrc")
			}
			ssrc := uint32(v)
			out.SSRC = &ssrc
			data = data[m:]
		case 4:
			v, m := protowire.ConsumeVarint(data)
			if m < 0 {
				return SenderSubscription{}, fmt.Errorf("invalid ssrcs")
			}
			out.SSRCs = append(out.SSRCs, uint32(v))
			data = data[m:]
		case 5:
			v, m := protowire.ConsumeVarint(data)
			if m < 0 {
				return SenderSubscription{}, fmt.Errorf("invalid stream_layer")
			}
			layer := VoIPStreamLayer(v)
			out.StreamLayer = &layer
			data = data[m:]
		case 6:
			v, m := protowire.ConsumeVarint(data)
			if m < 0 {
				return SenderSubscription{}, fmt.Errorf("invalid payload_type")
			}
			ptype := VoIPPayloadType(v)
			out.PayloadType = &ptype
			data = data[m:]
		default:
			skip, err := consumeUnknownWireValue(data, typ)
			if err != nil {
				return SenderSubscription{}, err
			}
			data = data[skip:]
		}
	}
	return out, nil
}

func consumeUnknownWireValue(data []byte, typ protowire.Type) (int, error) {
	switch typ {
	case protowire.VarintType:
		_, n := protowire.ConsumeVarint(data)
		if n < 0 {
			return 0, fmt.Errorf("invalid varint")
		}
		return n, nil
	case protowire.Fixed32Type:
		_, n := protowire.ConsumeFixed32(data)
		if n < 0 {
			return 0, fmt.Errorf("invalid fixed32")
		}
		return n, nil
	case protowire.Fixed64Type:
		_, n := protowire.ConsumeFixed64(data)
		if n < 0 {
			return 0, fmt.Errorf("invalid fixed64")
		}
		return n, nil
	case protowire.BytesType:
		_, n := protowire.ConsumeBytes(data)
		if n < 0 {
			return 0, fmt.Errorf("invalid bytes")
		}
		return n, nil
	default:
		return 0, fmt.Errorf("unsupported wire type %d", typ)
	}
}
