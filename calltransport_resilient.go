// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"fmt"
	"time"

	"go.mau.fi/whatsmeow/types"
)

// ResilientCallTransportConfig controls retry/reconnect behavior for transport writes.
type ResilientCallTransportConfig struct {
	Base               CallTransport
	SendRetries        int
	RetryBackoff       time.Duration
	ReconnectOnFailure bool
}

// ResilientCallTransport wraps another CallTransport with retry/backoff logic.
type ResilientCallTransport struct {
	cfg      ResilientCallTransportConfig
	incoming IncomingCallTransportPayloadHandler
}

// NewResilientCallTransport creates a retrying transport wrapper.
func NewResilientCallTransport(cfg ResilientCallTransportConfig) *ResilientCallTransport {
	if cfg.SendRetries < 0 {
		cfg.SendRetries = 0
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = 50 * time.Millisecond
	}
	if cfg.Base == nil {
		cfg.Base = &NoopCallTransport{}
	}
	return &ResilientCallTransport{cfg: cfg}
}

func (t *ResilientCallTransport) SetIncomingHandler(handler IncomingCallTransportPayloadHandler) {
	t.incoming = handler
	t.cfg.Base.SetIncomingHandler(handler)
}

func (t *ResilientCallTransport) Connect(ctx context.Context, info *types.CallInfo) error {
	if err := t.cfg.Base.Connect(ctx, info); err != nil {
		return fmt.Errorf("resilient transport connect failed: %w", err)
	}
	return nil
}

func (t *ResilientCallTransport) Close(ctx context.Context, info *types.CallInfo) error {
	if err := t.cfg.Base.Close(ctx, info); err != nil {
		return fmt.Errorf("resilient transport close failed: %w", err)
	}
	return nil
}

func (t *ResilientCallTransport) Send(ctx context.Context, info *types.CallInfo, payload []byte) error {
	attempts := t.cfg.SendRetries + 1
	var lastErr error
	for i := 0; i < attempts; i++ {
		err := t.cfg.Base.Send(ctx, info, payload)
		if err == nil {
			return nil
		}
		lastErr = err
		if i == attempts-1 {
			break
		}
		if t.cfg.ReconnectOnFailure {
			_ = t.cfg.Base.Close(ctx, info)
			_ = t.cfg.Base.Connect(ctx, info)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(t.cfg.RetryBackoff):
		}
	}
	return fmt.Errorf("resilient transport send failed after %d attempts: %w", attempts, lastErr)
}
