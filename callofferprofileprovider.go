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

// CallOfferProfileProvider can provide offer extensions before sending an
// outgoing offer (for example, runtime voip_settings/capability data).
type CallOfferProfileProvider interface {
	GetCallOfferExtensions(ctx context.Context, info *types.CallInfo) (*types.CallOfferExtensions, error)
}

// CallOfferProfileProviderFunc adapts a function into a CallOfferProfileProvider.
type CallOfferProfileProviderFunc func(ctx context.Context, info *types.CallInfo) (*types.CallOfferExtensions, error)

func (f CallOfferProfileProviderFunc) GetCallOfferExtensions(ctx context.Context, info *types.CallInfo) (*types.CallOfferExtensions, error) {
	return f(ctx, info)
}
