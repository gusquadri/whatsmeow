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

func TestApplyCallReliabilityConfigWrapsTransport(t *testing.T) {
	cli := &Client{}
	cm := NewCallManager(cli)
	cli.callManager = cm
	base := &testCallTransport{}
	cm.SetTransport(base)

	cfg := DefaultCallReliabilityConfig()
	cfg.MediaPumpInterval = 35 * time.Millisecond
	if err := cli.ApplyCallReliabilityConfig(cfg); err != nil {
		t.Fatalf("ApplyCallReliabilityConfig failed: %v", err)
	}
	if _, ok := cm.transport.(*ResilientCallTransport); !ok {
		t.Fatalf("expected transport to be wrapped by resilient transport")
	}
	if cm.mediaPumpInterval != 35*time.Millisecond {
		t.Fatalf("expected media pump interval to be applied, got %s", cm.mediaPumpInterval)
	}
}
