// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"

	"go.mau.fi/whatsmeow/types"
)

// CallMediaEngine is the Phase 3 media abstraction.
//
// Implementations (for example, RTP/SRTP pipelines) can be plugged in to
// process transport payloads and produce outbound media.
type CallMediaEngine interface {
	Start(ctx context.Context, info *types.CallInfo, keys *DerivedCallKeys) error
	Stop(ctx context.Context, info *types.CallInfo) error
	HandleIncomingPayload(ctx context.Context, info *types.CallInfo, payload []byte) error
}

// NoopCallMediaEngine is a safe default media engine used until a concrete
// Phase 3 media implementation is configured.
type NoopCallMediaEngine struct{}

func (n *NoopCallMediaEngine) Start(context.Context, *types.CallInfo, *DerivedCallKeys) error {
	return nil
}
func (n *NoopCallMediaEngine) Stop(context.Context, *types.CallInfo) error { return nil }
func (n *NoopCallMediaEngine) HandleIncomingPayload(context.Context, *types.CallInfo, []byte) error {
	return nil
}
