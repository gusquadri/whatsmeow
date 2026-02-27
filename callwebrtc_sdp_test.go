// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"encoding/base64"
	"strings"
	"testing"

	"go.mau.fi/whatsmeow/types"
)

func TestManipulateWebRTCOfferSDP(t *testing.T) {
	relay := WebRTCRelayConnectionInfo{
		IP:        "31.13.66.10",
		Port:      3480,
		AuthToken: "AUTH_TOKEN_FROM_SERVER",
		RelayKey:  "RELAY_KEY_16B!",
	}

	offer := strings.Join([]string{
		"v=0",
		"o=- 1 1 IN IP4 127.0.0.1",
		"s=-",
		"t=0 0",
		"m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
		"c=IN IP4 0.0.0.0",
		"a=setup:actpass",
		"a=ice-ufrag:ABCD",
		"a=ice-pwd:EFGHIJKLMNOP",
		"a=ice-options:trickle renomination",
		"a=fingerprint:sha-256 00:11:22:33",
		"a=candidate:1 1 udp 1234 192.168.1.2 45678 typ host",
		"a=end-of-candidates",
		"a=sctp-port:5000",
	}, "\r\n") + "\r\n"

	modified := ManipulateWebRTCOfferSDP(offer, relay)

	if !strings.Contains(modified, "a=setup:passive") {
		t.Fatalf("expected setup:passive in manipulated SDP")
	}
	if strings.Contains(modified, "a=setup:actpass") {
		t.Fatalf("unexpected setup:actpass in manipulated SDP")
	}
	if !strings.Contains(modified, "a=ice-ufrag:AUTH_TOKEN_FROM_SERVER") {
		t.Fatalf("expected replaced ice-ufrag")
	}
	if !strings.Contains(modified, "a=ice-pwd:RELAY_KEY_16B!") {
		t.Fatalf("expected replaced ice-pwd")
	}
	if !strings.Contains(modified, "a=fingerprint:"+WhatsAppWebDTLSFingerprint) {
		t.Fatalf("expected whatsapp fingerprint")
	}
	if strings.Contains(modified, "a=ice-options:") {
		t.Fatalf("expected ice-options to be removed")
	}
	if strings.Contains(modified, "a=candidate:1 1 udp") {
		t.Fatalf("expected original candidate to be removed")
	}
	if !strings.Contains(modified, "a=candidate:2 1 udp 2122262783 31.13.66.10 3480 typ host generation 0 network-cost 5") {
		t.Fatalf("expected relay-only candidate")
	}
	if !strings.Contains(modified, "a=end-of-candidates") {
		t.Fatalf("expected end-of-candidates")
	}
	if !strings.Contains(modified, "a=sctp-port:5000") {
		t.Fatalf("expected sctp-port to be preserved")
	}
}

func TestExtractWebRTCRelayConnectionInfo(t *testing.T) {
	fast := uint32(20)
	slow := uint32(120)

	relayData := &types.RelayData{
		RelayKey:    []byte{0x01, 0x02, 0x03, 0x04},
		RelayTokens: [][]byte{[]byte("relay-token-0")},
		AuthTokens:  [][]byte{[]byte("auth-token-0")},
		Endpoints: []types.RelayEndpoint{
			{
				RelayName:   "slow-relay",
				RelayID:     10,
				TokenID:     0,
				AuthTokenID: 0,
				C2RRTTMs:    &slow,
				Addresses: []types.RelayAddress{
					{Protocol: 0, IPv4: "10.0.0.10", Port: 3480},
				},
			},
			{
				RelayName:   "fast-relay",
				RelayID:     20,
				TokenID:     0,
				AuthTokenID: 99,
				C2RRTTMs:    &fast,
				Addresses: []types.RelayAddress{
					{Protocol: 0, IPv4: "10.0.0.20", Port: 0},
				},
			},
		},
	}

	infos, err := ExtractWebRTCRelayConnectionInfo(relayData)
	if err != nil {
		t.Fatalf("ExtractWebRTCRelayConnectionInfo failed: %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("unexpected relay count: got %d want 2", len(infos))
	}

	if infos[0].RelayName != "fast-relay" {
		t.Fatalf("unexpected relay order: first=%s want fast-relay", infos[0].RelayName)
	}
	if infos[0].Port != 3480 {
		t.Fatalf("expected default relay port fallback for zero port, got %d", infos[0].Port)
	}
	if infos[0].AuthToken != base64.StdEncoding.EncodeToString([]byte("relay-token-0")) {
		t.Fatalf("expected fallback to relay token for missing auth-token index")
	}

	if infos[1].RelayName != "slow-relay" {
		t.Fatalf("unexpected second relay: got %s want slow-relay", infos[1].RelayName)
	}
	if infos[1].AuthToken != base64.StdEncoding.EncodeToString([]byte("auth-token-0")) {
		t.Fatalf("expected auth token preference")
	}
	if infos[1].RelayKey != base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03, 0x04}) {
		t.Fatalf("unexpected relay key conversion")
	}
}

func TestExtractWebRTCRelayConnectionInfoIncludesProtocolOneAndDedupes(t *testing.T) {
	rtt := uint32(12)
	relayData := &types.RelayData{
		RelayKey:    []byte{0x10, 0x11, 0x12, 0x13},
		RelayTokens: [][]byte{[]byte("relay-token-0")},
		Endpoints: []types.RelayEndpoint{
			{
				RelayName:   "relay-a",
				RelayID:     1,
				TokenID:     0,
				AuthTokenID: 99,
				C2RRTTMs:    &rtt,
				Addresses: []types.RelayAddress{
					{Protocol: 1, IPv4: "10.0.0.5", Port: 3480},
					{Protocol: 0, IPv4: "10.0.0.5", Port: 3480}, // duplicate endpoint info (different protocol attr)
					{Protocol: 1, IPv6: "2001:db8::5", PortV6: 3480},
				},
			},
		},
	}

	infos, err := ExtractWebRTCRelayConnectionInfo(relayData)
	if err != nil {
		t.Fatalf("ExtractWebRTCRelayConnectionInfo failed: %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("expected deduped protocol 0/1 addresses, got %d entries", len(infos))
	}
	foundIPv4 := false
	foundIPv6 := false
	for _, info := range infos {
		if info.IP == "10.0.0.5" && info.Port == 3480 {
			foundIPv4 = true
		}
		if info.IP == "2001:db8::5" && info.Port == 3480 {
			foundIPv6 = true
		}
	}
	if !foundIPv4 || !foundIPv6 {
		t.Fatalf("expected both IPv4 and IPv6 candidates, got %+v", infos)
	}
}

func TestExpandWebRTCRelayCredentialVariants(t *testing.T) {
	base := []WebRTCRelayConnectionInfo{{
		IP:        "157.240.226.62",
		Port:      3480,
		AuthToken: "090314c470",
		RelayKey:  "RIUVWfuwxwn0K+SFu8ykSQ==",
		RelayName: "gru1c02",
		RelayID:   1,
	}}
	expanded := ExpandWebRTCRelayCredentialVariants(base)
	if len(expanded) == 0 {
		t.Fatalf("expected expanded relay list")
	}
	if len(expanded) > 4 {
		t.Fatalf("expected bounded variants (<=4), got %d", len(expanded))
	}
	foundOriginal := false
	seen := make(map[string]struct{}, len(expanded))
	for _, relay := range expanded {
		if relay.AuthToken == base[0].AuthToken && relay.RelayKey == base[0].RelayKey {
			foundOriginal = true
		}
		k := relay.AuthToken + "|" + relay.RelayKey
		if _, ok := seen[k]; ok {
			t.Fatalf("duplicate credential variant: %s", k)
		}
		seen[k] = struct{}{}
	}
	if !foundOriginal {
		t.Fatalf("expected original credentials to be retained")
	}
}
