// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import "time"

// CallReliabilityConfig defines production-oriented call reliability defaults.
type CallReliabilityConfig struct {
	TransportSendRetries   int
	TransportRetryBackoff  time.Duration
	TransportReconnectSend bool
	MediaPumpInterval      time.Duration
	RingTimeout            time.Duration
}

// DefaultCallReliabilityConfig returns conservative reliability defaults.
func DefaultCallReliabilityConfig() CallReliabilityConfig {
	return CallReliabilityConfig{
		TransportSendRetries:   3,
		TransportRetryBackoff:  100 * time.Millisecond,
		TransportReconnectSend: true,
		MediaPumpInterval:      20 * time.Millisecond,
		RingTimeout:            45 * time.Second,
	}
}

// ApplyCallReliabilityConfig applies reliability settings to call manager and transport.
func (cli *Client) ApplyCallReliabilityConfig(cfg CallReliabilityConfig) error {
	if cli.callManager == nil {
		return ErrNotLoggedIn
	}
	if cfg.RingTimeout > 0 {
		cli.callManager.SetRingTimeout(cfg.RingTimeout)
	}
	if cfg.MediaPumpInterval > 0 {
		cli.callManager.SetMediaPumpInterval(cfg.MediaPumpInterval)
	}
	if cfg.TransportRetryBackoff <= 0 {
		cfg.TransportRetryBackoff = 100 * time.Millisecond
	}
	if cfg.TransportSendRetries < 0 {
		cfg.TransportSendRetries = 0
	}

	cli.callManager.mu.RLock()
	current := cli.callManager.transport
	cli.callManager.mu.RUnlock()
	if current != nil {
		wrapped := NewResilientCallTransport(ResilientCallTransportConfig{
			Base:               current,
			SendRetries:        cfg.TransportSendRetries,
			RetryBackoff:       cfg.TransportRetryBackoff,
			ReconnectOnFailure: cfg.TransportReconnectSend,
		})
		cli.callManager.SetTransport(wrapped)
	}
	return nil
}
