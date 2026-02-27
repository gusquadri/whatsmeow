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

// CallRelayAllocator can provide relay/auth metadata before sending an outgoing
// offer, allowing first-call offers to include a relay block.
type CallRelayAllocator interface {
	AllocateRelayData(ctx context.Context, info *types.CallInfo) (*types.RelayData, error)
}

// CallRelayAllocatorFunc adapts a function into a CallRelayAllocator.
type CallRelayAllocatorFunc func(ctx context.Context, info *types.CallInfo) (*types.RelayData, error)

func (f CallRelayAllocatorFunc) AllocateRelayData(ctx context.Context, info *types.CallInfo) (*types.RelayData, error) {
	return f(ctx, info)
}

