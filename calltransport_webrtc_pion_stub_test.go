//go:build !pionwebrtc

// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"errors"
	"testing"
)

func TestPionWebRTCFactoryStub(t *testing.T) {
	_, err := NewPionWebRTCRelaySessionFactory(DefaultPionWebRTCSessionConfig())
	if !errors.Is(err, ErrPionWebRTCNotBuilt) {
		t.Fatalf("expected ErrPionWebRTCNotBuilt, got %v", err)
	}
}
