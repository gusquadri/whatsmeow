//go:build pionwebrtc

// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"encoding/base64"
	"testing"

	"go.mau.fi/whatsmeow/types"
)

func TestPionWebRTCFactoryBuilt(t *testing.T) {
	factory, err := NewPionWebRTCRelaySessionFactory(DefaultPionWebRTCSessionConfig())
	if err != nil {
		t.Fatalf("expected built pion factory, got error: %v", err)
	}
	if factory == nil {
		t.Fatalf("expected non-nil pion factory")
	}
}

func TestNewPionWebRTCAPIWithUDPMux(t *testing.T) {
	cfg := DefaultPionWebRTCSessionConfig()
	cfg.UseUDPMux = true
	cfg.UDPMuxListenAddr = "127.0.0.1:0"
	api, conn, err := newPionWebRTCAPI(cfg, nil)
	if err != nil {
		t.Fatalf("expected api creation, got error: %v", err)
	}
	if api == nil {
		t.Fatalf("expected non-nil api")
	}
	if conn == nil {
		t.Fatalf("expected non-nil udp mux conn")
	}
	_ = conn.Close()
}

func TestDecodeMaybeBase64(t *testing.T) {
	raw := []byte{1, 2, 3, 4}
	encoded := base64.StdEncoding.EncodeToString(raw)
	decoded := decodeMaybeBase64(encoded)
	if len(decoded) != len(raw) {
		t.Fatalf("unexpected decoded length: got %d want %d", len(decoded), len(raw))
	}
	for i := range raw {
		if decoded[i] != raw[i] {
			t.Fatalf("unexpected decoded bytes")
		}
	}
}

func TestDecodeMaybeBase64RawEncoding(t *testing.T) {
	raw := []byte{0x90, 0x03, 0x14, 0xC4, 0x70}
	encoded := base64.RawStdEncoding.EncodeToString(raw)
	decoded := decodeMaybeBase64(encoded)
	if len(decoded) != len(raw) {
		t.Fatalf("unexpected decoded length: got %d want %d", len(decoded), len(raw))
	}
	for i := range raw {
		if decoded[i] != raw[i] {
			t.Fatalf("unexpected decoded bytes at %d", i)
		}
	}
}

func TestDecodeMaybeBase64HexFallback(t *testing.T) {
	decoded := decodeMaybeBase64("090314c470")
	want := []byte{0x09, 0x03, 0x14, 0xC4, 0x70}
	if len(decoded) != len(want) {
		t.Fatalf("unexpected decoded length: got %d want %d", len(decoded), len(want))
	}
	for i := range want {
		if decoded[i] != want[i] {
			t.Fatalf("unexpected decoded bytes at %d", i)
		}
	}
}

func TestDefaultPionWebRTCSessionConfigHardeningDefaults(t *testing.T) {
	cfg := DefaultPionWebRTCSessionConfig()
	if cfg.UseUDPMux {
		t.Fatalf("expected UDPMux disabled by default for browser parity")
	}
	if cfg.ForceUDP4Only {
		t.Fatalf("expected dual-stack mode by default")
	}
	if !cfg.DisableMDNS {
		t.Fatalf("expected mDNS disabled by default")
	}
	if !cfg.DisableFingerprint {
		t.Fatalf("expected fingerprint verification disabled by default")
	}
	if !cfg.ForceDTLSClientRole {
		t.Fatalf("expected DTLS client role enforcement by default")
	}
	if cfg.EnableCredentialVariantFallback {
		t.Fatalf("expected credential variant fallback disabled by default")
	}
	if cfg.PreflightSTUN {
		t.Fatalf("expected preflight STUN disabled by default")
	}
	if cfg.OutOfBandSTUNRefresh {
		t.Fatalf("expected out-of-band STUN refresh disabled by default")
	}
}

func TestStunCredentialProfilesFromRelayStrictMode(t *testing.T) {
	relay := WebRTCRelayConnectionInfo{
		AuthToken: "CQOO22fTxf6YNBE+idWeRIGsTprv0S43zveDuXiMGvOKWsaz8Fzev3k6l5WyerXNwFXLPn4vDf7W1mh3MfAyQ6+Pb9scjg==",
		RelayKey:  "sLpwahpqvXV85Pd6VhkQ8A==",
	}
	profiles := stunCredentialProfilesFromRelay(relay, false)
	if len(profiles) != 1 {
		t.Fatalf("expected strict mode to keep exactly one profile, got %d", len(profiles))
	}
	if profiles[0].label != "text" {
		t.Fatalf("expected strict profile label 'text', got %q", profiles[0].label)
	}
}

func TestStunCredentialProfilesFromRelayFallbackMode(t *testing.T) {
	relay := WebRTCRelayConnectionInfo{
		AuthToken: "090314c470",
		RelayKey:  "RIUVWfuwxwn0K+SFu8ykSQ==",
	}
	profiles := stunCredentialProfilesFromRelay(relay, true)
	if len(profiles) < 2 {
		t.Fatalf("expected fallback mode to add alternate profiles, got %d", len(profiles))
	}
}

func TestDeriveSTUNSenderSSRCDeterministic(t *testing.T) {
	a := deriveSTUNSenderSSRC("call-123")
	b := deriveSTUNSenderSSRC("call-123")
	c := deriveSTUNSenderSSRC("call-124")
	if a == 0 || b == 0 {
		t.Fatalf("expected non-zero derived ssrc")
	}
	if a != b {
		t.Fatalf("expected deterministic derived ssrc for same call id")
	}
	if c == a {
		t.Fatalf("expected different call ids to usually map to different ssrc values")
	}
}

func TestBuildSTUNSenderSubscriptionsUsesCallID(t *testing.T) {
	subDefault := buildSTUNSenderSubscriptions(nil)
	if len(subDefault) == 0 {
		t.Fatalf("expected non-empty default sender subscriptions")
	}
	decodedDefault, err := DecodeSenderSubscriptions(subDefault)
	if err != nil {
		t.Fatalf("failed to decode default sender subscriptions: %v", err)
	}
	if len(decodedDefault.Senders) != 3 {
		t.Fatalf("expected 3 stream descriptors, got %d", len(decodedDefault.Senders))
	}
	expectedLayers := map[VoIPStreamLayer]bool{
		StreamLayerAudio:        false,
		StreamLayerVideoStream0: false,
		StreamLayerVideoStream1: false,
	}
	for _, sender := range decodedDefault.Senders {
		if sender.StreamLayer == nil {
			t.Fatalf("expected stream layer in sender descriptor")
		}
		if _, ok := expectedLayers[*sender.StreamLayer]; !ok {
			t.Fatalf("unexpected stream layer: %v", *sender.StreamLayer)
		}
		expectedLayers[*sender.StreamLayer] = true
		if sender.SSRC == nil || *sender.SSRC == 0 {
			t.Fatalf("expected non-zero media ssrc")
		}
		if len(sender.SSRCs) != 2 || sender.SSRCs[0] == 0 || sender.SSRCs[1] == 0 {
			t.Fatalf("expected fec+nack ssrc list, got %+v", sender.SSRCs)
		}
		if sender.PayloadType == nil || *sender.PayloadType != PayloadTypeMedia {
			t.Fatalf("expected media payload type")
		}
	}
	for layer, seen := range expectedLayers {
		if !seen {
			t.Fatalf("missing stream layer descriptor: %v", layer)
		}
	}

	subA := buildSTUNSenderSubscriptions(&types.CallInfo{CallID: "call-a"})
	subB := buildSTUNSenderSubscriptions(&types.CallInfo{CallID: "call-b"})
	if len(subA) == 0 || len(subB) == 0 {
		t.Fatalf("expected non-empty sender subscriptions for call info")
	}
	if string(subA) == string(subB) {
		t.Fatalf("expected sender subscriptions to differ across call ids")
	}
}
