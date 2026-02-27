// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

// WebRTCTransportState represents the current connection state of the
// WhatsApp-Web-style WebRTC relay transport.
type WebRTCTransportState int

const (
	WebRTCTransportStateIdle WebRTCTransportState = iota
	WebRTCTransportStateCreatingOffer
	WebRTCTransportStateConnecting
	WebRTCTransportStateConnected
	WebRTCTransportStateFailed
	WebRTCTransportStateClosed
)

func (s WebRTCTransportState) String() string {
	switch s {
	case WebRTCTransportStateIdle:
		return "idle"
	case WebRTCTransportStateCreatingOffer:
		return "creating_offer"
	case WebRTCTransportStateConnecting:
		return "connecting"
	case WebRTCTransportStateConnected:
		return "connected"
	case WebRTCTransportStateFailed:
		return "failed"
	case WebRTCTransportStateClosed:
		return "closed"
	default:
		return "unknown"
	}
}
