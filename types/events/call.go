// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package events

import (
	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
)

// CallOffer is emitted when the user receives a call on WhatsApp.
type CallOffer struct {
	types.BasicCallMeta
	types.CallRemoteMeta

	StanzaID           string
	IsVideo            bool               // Whether this is a video call
	MediaParams        *types.MediaParams // Parsed audio/video codec parameters
	RelayData          *types.RelayData   // Parsed relay endpoint information
	Joinable           bool
	CallerCountryCode  string
	Capability         []byte
	Metadata           *types.CallOfferMetadata
	RTE                []byte
	HasUploadFieldStat bool
	VoIPSettings       string

	Data *waBinary.Node // The raw call offer data
}

// CallAccept is emitted when a call is accepted on WhatsApp.
type CallAccept struct {
	types.BasicCallMeta
	types.CallRemoteMeta

	Data *waBinary.Node
}

// CallOfferReceipt is emitted when offer receipt signaling is received.
type CallOfferReceipt struct {
	types.BasicCallMeta
	Data *waBinary.Node
}

// CallAcceptReceipt is emitted when accept receipt signaling is received.
type CallAcceptReceipt struct {
	types.BasicCallMeta
	Data *waBinary.Node
}

// CallPreAccept is emitted when the remote party signals ringing state.
type CallPreAccept struct {
	types.BasicCallMeta
	types.CallRemoteMeta

	Data *waBinary.Node
}

// CallTransport is emitted when ICE transport candidates are exchanged.
type CallTransport struct {
	types.BasicCallMeta
	types.CallRemoteMeta

	Data          *waBinary.Node
	TransportData *types.TransportPayload
}

// CallOfferNotice is emitted when the user receives a notice of a call on WhatsApp.
// This seems to be primarily for group calls (whereas CallOffer is for 1:1 calls).
type CallOfferNotice struct {
	types.BasicCallMeta

	Media string // "audio" or "video" depending on call type
	Type  string // "group" when it's a group call

	Data *waBinary.Node
}

// CallRelayLatency is emitted slightly after the user receives a call on WhatsApp.
type CallRelayLatency struct {
	types.BasicCallMeta
	Data *waBinary.Node
}

// CallRelayElection is emitted when the server selects which relay to use for the call.
type CallRelayElection struct {
	types.BasicCallMeta
	Data         *waBinary.Node
	ElectedRelay *types.RelayElectionData
}

// CallTerminate is emitted when the other party terminates a call on WhatsApp.
type CallTerminate struct {
	types.BasicCallMeta
	Reason string
	Data   *waBinary.Node
}

// CallReject is sent when the other party rejects the call on WhatsApp.
type CallReject struct {
	types.BasicCallMeta
	Data *waBinary.Node
}

// CallEncRekey is emitted when the remote party sends an encryption key renegotiation.
type CallEncRekey struct {
	types.BasicCallMeta
	Data    *waBinary.Node
	EncData *types.OfferEncData
	Rekey   *types.EncRekeyData
}

// CallMuteState is emitted when the remote party changes their mute state.
type CallMuteState struct {
	types.BasicCallMeta
	Data *waBinary.Node
}

// CallInterruption is emitted when a call interruption event is received.
type CallInterruption struct {
	types.BasicCallMeta
	Data *waBinary.Node
}

// CallVideoState is emitted when video state changes are signaled.
type CallVideoState struct {
	types.BasicCallMeta
	Data *waBinary.Node
}

// CallVideoStateAck is emitted when video state acknowledgements are received.
type CallVideoStateAck struct {
	types.BasicCallMeta
	Data *waBinary.Node
}

// CallNotify is emitted for generic call notification signaling.
type CallNotify struct {
	types.BasicCallMeta
	Data *waBinary.Node
}

// CallGroupInfo is emitted for group call info signaling.
type CallGroupInfo struct {
	types.BasicCallMeta
	Data *waBinary.Node
}

// CallPeerState is emitted when peer state signaling is received.
type CallPeerState struct {
	types.BasicCallMeta
	Data *waBinary.Node
}

// CallFlowControl is emitted when flow control signaling is received.
type CallFlowControl struct {
	types.BasicCallMeta
	Data *waBinary.Node
}

// CallWebClient is emitted for web-client-specific call signaling.
type CallWebClient struct {
	types.BasicCallMeta
	Data *waBinary.Node
}

// CallAcceptAck is emitted when accept-ack signaling is received.
type CallAcceptAck struct {
	types.BasicCallMeta
	Data *waBinary.Node
}

// CallGroupUpdate is emitted when group update signaling is received.
type CallGroupUpdate struct {
	types.BasicCallMeta
	Data *waBinary.Node
}

// CallOfferAckRelay is emitted when the server ACKs an outgoing offer with relay allocation data.
type CallOfferAckRelay struct {
	CallID             string
	StanzaID           string
	RelayData          *types.RelayData
	RTE                []byte
	HasUploadFieldStat bool
	Joinable           bool
	VoIPSettingsByJID  map[types.JID]string
	UserDevices        map[types.JID][]types.JID
	Data               *waBinary.Node
}

// CallTransportConnected is emitted when the transport transitions to connected.
type CallTransportConnected struct {
	CallID string
}

// CallTransportFailed is emitted when transport setup fails.
type CallTransportFailed struct {
	CallID string
	Reason string
}

// CallWebRTCTransportState is emitted when WebRTC transport state changes.
type CallWebRTCTransportState struct {
	CallID string
	State  string
	Reason string
}

// CallTransportPayload is emitted when transport payload data is received.
type CallTransportPayload struct {
	CallID  string
	Payload []byte
}

// CallMediaStarted is emitted when the media pipeline transitions to active.
type CallMediaStarted struct {
	CallID string
}

// CallMediaStopped is emitted when the media pipeline is stopped.
type CallMediaStopped struct {
	CallID string
	Reason string
}

// CallMediaStats is emitted when media traffic counters are updated.
type CallMediaStats struct {
	CallID string
	Stats  types.CallMediaStats
}

// CallMediaFailed is emitted when media setup or processing fails.
type CallMediaFailed struct {
	CallID string
	Reason string
}

// CallTimeout is emitted when a ringing call expires by timeout.
type CallTimeout struct {
	CallID string
}

// UnknownCallEvent is emitted when a call element with unknown content is received.
type UnknownCallEvent struct {
	Node *waBinary.Node
}
