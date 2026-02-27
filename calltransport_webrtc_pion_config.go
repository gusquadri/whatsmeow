// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"errors"
	"time"
)

// ErrPionWebRTCNotBuilt is returned when Pion-backed WebRTC was requested
// without compiling with the `pionwebrtc` build tag.
var ErrPionWebRTCNotBuilt = errors.New("pion webrtc backend not built; compile with -tags pionwebrtc")

// PionWebRTCSessionConfig configures the Pion WebRTC session backend.
type PionWebRTCSessionConfig struct {
	ConnectTimeout time.Duration
	PreflightSTUN  bool
	// EnableCredentialVariantFallback enables non-parity credential permutations
	// (alternate SDP/ICE encodings) for troubleshooting only.
	EnableCredentialVariantFallback bool
	TieBreaker                      uint64
	KeepaliveInterval               time.Duration
	OutOfBandSTUNRefresh            bool
	DisableMDNS                     bool
	ForceUDP4Only                   bool
	UseUDPMux                       bool
	UDPMuxListenAddr                string
	DisableFingerprint bool
	// ForceDTLSClientRole sets SetAnsweringDTLSRole(DTLSRoleClient) on the
	// Pion SettingEngine. Note: this only takes effect when Pion creates an
	// answer. In the current architecture we always create an offer and feed
	// back a synthetic answer with a=setup:passive, which already forces
	// Pion to the DTLS client (active) role. This setting is kept as a
	// safety fallback but is not required for normal operation.
	ForceDTLSClientRole bool
	ICEDisconnectedAfter            time.Duration
	ICEFailedAfter                  time.Duration
	ICEKeepaliveInterval            time.Duration
}

// DefaultPionWebRTCSessionConfig returns default Pion backend config.
func DefaultPionWebRTCSessionConfig() PionWebRTCSessionConfig {
	return PionWebRTCSessionConfig{
		ConnectTimeout: 12 * time.Second,
		// Prefer browser-like ICE behavior by default; legacy bind preflight can
		// still be enabled explicitly for troubleshooting.
		PreflightSTUN:        false,
		TieBreaker:           0,
		KeepaliveInterval:    2500 * time.Millisecond,
		OutOfBandSTUNRefresh: false,
		DisableMDNS:          true,
		ForceUDP4Only:        false,
		UseUDPMux:            false,
		UDPMuxListenAddr:     "",
		DisableFingerprint:   true,
		ForceDTLSClientRole:  true,
		ICEDisconnectedAfter: 5 * time.Second,
		ICEFailedAfter:       25 * time.Second,
		ICEKeepaliveInterval: 2 * time.Second,
	}
}

// normalizePionWebRTCSessionConfig applies runtime-safe defaults.
//
// A fully zero-value config is treated as "use hardened defaults", which
// preserves compatibility with reflective integrations that call
// UsePionWebRTCTransport() without arguments.
func normalizePionWebRTCSessionConfig(cfg PionWebRTCSessionConfig) PionWebRTCSessionConfig {
	if cfg == (PionWebRTCSessionConfig{}) {
		return DefaultPionWebRTCSessionConfig()
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 12 * time.Second
	}
	if cfg.KeepaliveInterval <= 0 {
		cfg.KeepaliveInterval = 2500 * time.Millisecond
	}
	if cfg.ICEDisconnectedAfter <= 0 {
		cfg.ICEDisconnectedAfter = 5 * time.Second
	}
	if cfg.ICEFailedAfter <= 0 {
		cfg.ICEFailedAfter = 25 * time.Second
	}
	if cfg.ICEKeepaliveInterval <= 0 {
		cfg.ICEKeepaliveInterval = 2 * time.Second
	}
	return cfg
}
