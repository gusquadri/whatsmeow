//go:build !pionwebrtc

// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import "context"

// NewPionWebRTCRelaySessionFactory returns an error unless built with
// `-tags pionwebrtc`.
func NewPionWebRTCRelaySessionFactory(_ PionWebRTCSessionConfig) (WebRTCRelaySessionFactory, error) {
	return nil, ErrPionWebRTCNotBuilt
}

// UsePionWebRTCTransport configures call transport to the Pion-backed WebRTC
// transport when available.
func (cli *Client) UsePionWebRTCTransport(cfg PionWebRTCSessionConfig) error {
	if cli.callManager == nil {
		return ErrNotLoggedIn
	}
	factory, err := NewPionWebRTCRelaySessionFactory(cfg)
	if err != nil {
		return err
	}
	transport := NewWebRTCRelayCallTransport(WebRTCRelayCallTransportConfig{SessionFactory: factory})
	return cli.SetCallTransport(transport)
}

// AttemptWebRTCPreflightSTUN is a stub in non-pion builds.
func AttemptWebRTCPreflightSTUN(context.Context, WebRTCRelayConnectionInfo, []byte, []byte, uint64) error {
	return ErrPionWebRTCNotBuilt
}
