// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package types

import "time"

type BasicCallMeta struct {
	From           JID
	Timestamp      time.Time
	CallCreator    JID
	CallCreatorAlt JID
	CallID         string
	GroupJID       JID
}

type CallRemoteMeta struct {
	RemotePlatform string // The platform of the caller's WhatsApp client
	RemoteVersion  string // Version of the caller's WhatsApp client
}

// SignalingType represents a WhatsApp call signaling message type.
type SignalingType int

const (
	SignalingNone          SignalingType = 0
	SignalingOffer         SignalingType = 1
	SignalingOfferReceipt  SignalingType = 2
	SignalingAccept        SignalingType = 3
	SignalingReject        SignalingType = 4
	SignalingTerminate     SignalingType = 5
	SignalingTransport     SignalingType = 6
	SignalingOfferAck      SignalingType = 7
	SignalingOfferNack     SignalingType = 8
	SignalingRelayLatency  SignalingType = 9
	SignalingRelayElection SignalingType = 10
	SignalingInterruption  SignalingType = 11
	SignalingMute          SignalingType = 12
	SignalingPreAccept     SignalingType = 13
	SignalingAcceptReceipt SignalingType = 14
	SignalingVideoState    SignalingType = 15
	SignalingNotify        SignalingType = 16
	SignalingGroupInfo     SignalingType = 17
	SignalingEncRekey      SignalingType = 18
	SignalingPeerState     SignalingType = 19
	SignalingVideoStateAck SignalingType = 20
	SignalingFlowControl   SignalingType = 21
	SignalingWebClient     SignalingType = 22
	SignalingAcceptAck     SignalingType = 23
	SignalingGroupUpdate   SignalingType = 24
	SignalingOfferNotice   SignalingType = 25
	SignalingMuteV2        SignalingType = 26
)

// ResponseType indicates what kind of response a signaling type requires.
type ResponseType int

const (
	ResponseTypeNone    ResponseType = 0
	ResponseTypeAck     ResponseType = 1
	ResponseTypeReceipt ResponseType = 2
)

var signalingTagMap = map[SignalingType]string{
	SignalingOffer:         "offer",
	SignalingOfferReceipt:  "offer_receipt",
	SignalingAccept:        "accept",
	SignalingReject:        "reject",
	SignalingTerminate:     "terminate",
	SignalingTransport:     "transport",
	SignalingOfferAck:      "offer_ack",
	SignalingOfferNack:     "offer_nack",
	SignalingRelayLatency:  "relaylatency",
	SignalingRelayElection: "relay_election",
	SignalingInterruption:  "interruption",
	SignalingMute:          "mute",
	SignalingPreAccept:     "preaccept",
	SignalingAcceptReceipt: "accept_receipt",
	SignalingVideoState:    "video_state",
	SignalingNotify:        "notify",
	SignalingGroupInfo:     "group_info",
	SignalingEncRekey:      "enc_rekey",
	SignalingPeerState:     "peer_state",
	SignalingVideoStateAck: "video_state_ack",
	SignalingFlowControl:   "flow_control",
	SignalingWebClient:     "web_client",
	SignalingAcceptAck:     "accept_ack",
	SignalingGroupUpdate:   "group_update",
	SignalingOfferNotice:   "offer_notice",
	SignalingMuteV2:        "mute_v2",
}

var tagSignalingMap map[string]SignalingType

func init() {
	tagSignalingMap = make(map[string]SignalingType, len(signalingTagMap))
	for st, tag := range signalingTagMap {
		tagSignalingMap[tag] = st
	}
}

// Tag returns the XML tag name for this signaling type.
func (st SignalingType) Tag() string {
	if tag, ok := signalingTagMap[st]; ok {
		return tag
	}
	return ""
}

// GetResponseType returns what kind of protocol response this signaling type requires.
func (st SignalingType) GetResponseType() ResponseType {
	switch st {
	case SignalingOffer, SignalingAccept, SignalingReject, SignalingEncRekey:
		return ResponseTypeReceipt
	case SignalingNone:
		return ResponseTypeNone
	default:
		return ResponseTypeAck
	}
}

// SignalingTypeFromTag converts an XML tag name to a SignalingType.
func SignalingTypeFromTag(tag string) SignalingType {
	if st, ok := tagSignalingMap[tag]; ok {
		return st
	}
	return SignalingNone
}

// CallState represents the current state of a call.
type CallState int

const (
	CallStateInitiating      CallState = iota // Before offer sent/received
	CallStateRinging                          // Outgoing: offer sent, waiting for response
	CallStateIncomingRinging                  // Incoming: offer received, waiting for user action
	CallStateConnecting                       // Accepted, establishing media connection
	CallStateActive                           // Media connected, call in progress
	CallStateOnHold                           // Call put on hold
	CallStateEnded                            // Call ended
)

// CallOptions specifies options for starting a new call.
type CallOptions struct {
	Video           bool
	GroupJID        JID
	OfferExtensions *CallOfferExtensions
	RelayData       *RelayData
}

// AudioParams describes audio codec parameters for a call.
type AudioParams struct {
	Codec string // e.g., "opus"
	Rate  uint32 // e.g., 8000, 16000
}

// VideoParams describes video codec parameters for a call.
type VideoParams struct {
	Codec string // e.g., "vp8", "h264"
}

// MediaParams contains the media parameters from a call offer/accept.
type MediaParams struct {
	Audio []AudioParams
	Video *VideoParams
}

// RelayAddress contains IP address information for a relay endpoint.
type RelayAddress struct {
	IPv4     string
	IPv6     string
	Port     uint16
	PortV6   uint16
	Protocol uint8
}

// RelayEndpoint describes a single relay server endpoint.
type RelayEndpoint struct {
	RelayID     uint32
	RelayName   string
	TokenID     uint32
	AuthTokenID uint32
	Addresses   []RelayAddress
	C2RRTTMs    *uint32
}

// RelayParticipant describes a participant entry inside relay metadata.
type RelayParticipant struct {
	JID JID
	PID uint32
}

// RelayData contains parsed relay connection information from a call stanza.
type RelayData struct {
	AttributePadding bool
	HBHKey           []byte // 30 bytes: 16-byte key + 14-byte salt
	RelayKey         []byte // 16 bytes
	UUID             string
	SelfPID          uint32
	PeerPID          uint32
	Participants     []RelayParticipant
	RelayTokens      [][]byte
	AuthTokens       [][]byte
	Endpoints        []RelayEndpoint
}

// CallOfferMetadata describes optional metadata carried in call offers.
type CallOfferMetadata struct {
	PeerABTestBucket       string
	PeerABTestBucketIDList string
}

// CallOfferExtensions holds optional offer fields used by WhatsApp clients.
type CallOfferExtensions struct {
	Joinable          bool
	CallerCountryCode string
	Privacy           []byte
	Capability        []byte
	Metadata          *CallOfferMetadata
	RTE               []byte
	UploadFieldStat   bool
	VoIPSettings      string
}

// OfferEncData contains the encrypted call key data from an offer stanza.
type OfferEncData struct {
	EncType    string // "msg" or "pkmsg"
	Ciphertext []byte
	Version    int
}

// EncRekeyData contains the encrypted call key data from an enc_rekey stanza.
type EncRekeyData struct {
	EncType    string // "msg" or "pkmsg"
	Ciphertext []byte
	Count      uint32
}

// RelayLatencyMeasurement represents a single relay latency measurement.
type RelayLatencyMeasurement struct {
	RelayID    uint32
	RelayName  string
	LatencyMs  uint32
	RawLatency uint32
	IPv4       string
	IPv6       string
	Port       uint16
}

// RelayElectionData contains the result of relay election by the server.
type RelayElectionData struct {
	ElectedRelayIndex uint32
}

// TransportCandidate represents a single ICE candidate exchanged in call transport payloads.
type TransportCandidate struct {
	Candidate     string
	SDPMid        string
	SDPMLineIndex *uint16
	UsernameFrag  string
}

// TransportPayload represents parsed call transport payload data.
//
// RawData is always populated when payload bytes are available. If the payload
// appears to be JSON, common ICE fields are parsed into the structured fields.
type TransportPayload struct {
	RawData    []byte
	Ufrag      string
	Pwd        string
	Candidates []TransportCandidate
}

// TransportState represents the state of the Phase 2 call transport connection.
type TransportState int

const (
	TransportStateNone TransportState = iota
	TransportStatePendingRelay
	TransportStateConnecting
	TransportStateConnected
	TransportStateFailed
)

// MediaState represents the state of the Phase 3 media pipeline for a call.
type MediaState int

const (
	MediaStateNone MediaState = iota
	MediaStateStarting
	MediaStateActive
	MediaStateStopping
	MediaStateFailed
)

// CallMediaStats holds basic media traffic counters for a call.
type CallMediaStats struct {
	PacketsSent     uint64
	PacketsReceived uint64
	BytesSent       uint64
	BytesReceived   uint64
	LastPacketSent  time.Time
	LastPacketRecv  time.Time
}

// CallInfo holds all information about an active or recent call.
type CallInfo struct {
	CallID      string
	PeerJID     JID
	CallCreator JID
	CallerPN    JID
	GroupJID    JID
	State       CallState
	IsVideo     bool
	IsInitiator bool

	// Timestamps
	StartedAt    time.Time
	AcceptedAt   time.Time
	ConnectedAt  time.Time
	EndedAt      time.Time
	RingDeadline time.Time

	// Media negotiation
	MediaParams       *MediaParams
	RelayData         *RelayData
	OfferExtensions   *CallOfferExtensions
	OfferAckRTE       []byte
	OfferAckVoIPByJID map[JID]string
	OfferAckDevices   map[JID][]JID
	OfferStanzaID     string
	RelayAllocatedAt  time.Time

	// Encryption
	OfferEncData *OfferEncData

	// Relay election
	ElectedRelayIndex          *uint32
	TransportState             TransportState
	TransportConnectInFly      int
	TransportConnectedNotified bool
	TransportAttemptSeq        uint64
	TransportLastAttemptID     string
	TransportLastAttemptSource string
	TransportLastAttemptError  string
	TransportLastAttemptAt     time.Time
	TransportRetryQueued       bool
	TransportRetryQueuedSource string
	TransportRetryQueuedAt     time.Time

	// Phase 3 media state
	MediaState     MediaState
	MediaStats     CallMediaStats
	MediaStartedAt time.Time
	MediaStoppedAt time.Time
	MediaLastError string

	// Retry/timeout bookkeeping
	RetryCount int
}
