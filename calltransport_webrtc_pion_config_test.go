// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"testing"
	"time"
)

func TestNormalizePionWebRTCSessionConfigZeroUsesDefaults(t *testing.T) {
	cfg := normalizePionWebRTCSessionConfig(PionWebRTCSessionConfig{})
	def := DefaultPionWebRTCSessionConfig()
	if cfg != def {
		t.Fatalf("expected zero-value config to normalize to defaults:\n got: %#v\nwant: %#v", cfg, def)
	}
}

func TestNormalizePionWebRTCSessionConfigPreservesExplicitFlags(t *testing.T) {
	cfg := normalizePionWebRTCSessionConfig(PionWebRTCSessionConfig{
		ConnectTimeout: 3 * time.Second,
		PreflightSTUN:  false,
		UseUDPMux:      false,
	})
	if cfg.ConnectTimeout != 3*time.Second {
		t.Fatalf("expected explicit connect timeout to be preserved, got %s", cfg.ConnectTimeout)
	}
	if cfg.PreflightSTUN {
		t.Fatalf("expected explicit preflight=false to be preserved")
	}
	if cfg.UseUDPMux {
		t.Fatalf("expected explicit udpmux=false to be preserved")
	}
	if cfg.KeepaliveInterval <= 0 {
		t.Fatalf("expected keepalive interval defaulting for partial config")
	}
}

