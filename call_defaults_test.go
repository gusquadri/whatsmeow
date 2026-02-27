// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import "testing"

func TestCallManagerDefaults(t *testing.T) {
	cm := NewCallManager(&Client{})
	if cm == nil {
		t.Fatalf("expected call manager")
	}
	if _, ok := cm.transport.(*NoopCallTransport); !ok {
		t.Fatalf("expected default transport to be noop")
	}
	if _, ok := cm.mediaEngine.(*RTPCallMediaEngine); !ok {
		t.Fatalf("expected default media engine to be RTPCallMediaEngine")
	}
}

func TestSetMediaEngineNilResetsToDefault(t *testing.T) {
	cm := NewCallManager(&Client{})
	cm.SetMediaEngine(nil)
	if _, ok := cm.mediaEngine.(*RTPCallMediaEngine); !ok {
		t.Fatalf("expected nil media engine to reset to default RTPCallMediaEngine")
	}
}
