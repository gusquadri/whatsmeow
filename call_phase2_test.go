// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
)

func buildOfferAckNode(stanzaID string) *waBinary.Node {
	hbhRaw := []byte{1, 1, 1, 1}
	relayKeyRaw := []byte{2, 2, 2, 2}
	peerUser := types.NewJID("155500001", types.DefaultUserServer)
	peerDeviceA := types.NewJID("155500001", types.DefaultUserServer).ToNonAD()
	peerDeviceA.Device = 8
	peerDeviceB := types.NewJID("155500001", types.DefaultUserServer).ToNonAD()
	peerDeviceB.Device = 26
	return &waBinary.Node{
		Tag: "ack",
		Attrs: waBinary.Attrs{
			"id":    stanzaID,
			"class": "call",
			"type":  "offer",
		},
		Content: []waBinary.Node{
			{
				Tag: "relay",
				Attrs: waBinary.Attrs{
					"uuid":     "relay-uuid",
					"self_pid": "3",
					"peer_pid": "1",
					"joinable": "1",
				},
				Content: []waBinary.Node{
					{Tag: "hbh_key", Content: base64.StdEncoding.EncodeToString(hbhRaw)},
					{Tag: "key", Content: base64.StdEncoding.EncodeToString(relayKeyRaw)},
					{Tag: "token", Attrs: waBinary.Attrs{"id": "0"}, Content: []byte("token-0")},
					{Tag: "auth_token", Attrs: waBinary.Attrs{"id": "0"}, Content: []byte("auth-0")},
					{
						Tag: "te2",
						Attrs: waBinary.Attrs{
							"relay_id":      "2",
							"relay_name":    "for2c02",
							"token_id":      "0",
							"auth_token_id": "0",
							"protocol":      "1",
							"c2r_rtt":       "42",
						},
						Content: []byte{10, 20, 30, 40, 0x0D, 0x98},
					},
				},
			},
			{
				Tag:   "user",
				Attrs: waBinary.Attrs{"jid": peerUser},
				Content: []waBinary.Node{
					{Tag: "device", Attrs: waBinary.Attrs{"jid": peerUser}},
					{Tag: "device", Attrs: waBinary.Attrs{"jid": peerDeviceA}},
					{Tag: "device", Attrs: waBinary.Attrs{"jid": peerDeviceB}},
				},
			},
			{Tag: "rte", Content: []byte{0x28, 0x04, 0x51, 0x28}},
			{Tag: "uploadfieldstat"},
			{
				Tag:     "voip_settings",
				Attrs:   waBinary.Attrs{"uncompressed": "1", "jid": peerUser},
				Content: `{"options":{"disable_p2p":"1"}}`,
			},
		},
	}
}

func TestParseRelayDataFromCallAck(t *testing.T) {
	relayData := ParseRelayDataFromCallAck(buildOfferAckNode("ack-1"))
	if relayData == nil {
		t.Fatalf("expected relay data from call offer ack")
	}
	if len(relayData.Endpoints) != 1 {
		t.Fatalf("expected one endpoint, got %d", len(relayData.Endpoints))
	}
	endpoint := relayData.Endpoints[0]
	if endpoint.C2RRTTMs == nil || *endpoint.C2RRTTMs != 42 {
		t.Fatalf("unexpected c2r_rtt parsing: %+v", endpoint.C2RRTTMs)
	}
	if len(endpoint.Addresses) != 1 || endpoint.Addresses[0].Protocol != 1 {
		t.Fatalf("unexpected protocol parsing in relay address")
	}
}

func TestParseRelayDataFromCallAckMergesDuplicateRelayEntries(t *testing.T) {
	node := buildOfferAckNode("ack-dup-relay")
	children := node.GetChildren()
	if len(children) == 0 {
		t.Fatalf("expected relay child in offer ack fixture")
	}
	relay := children[0]
	relayChildren, ok := relay.Content.([]waBinary.Node)
	if !ok {
		t.Fatalf("unexpected relay content type")
	}
	relayChildren = append(
		relayChildren,
		waBinary.Node{
			Tag: "te2",
			Attrs: waBinary.Attrs{
				"relay_id":      "2",
				"relay_name":    "for2c02",
				"token_id":      "0",
				"auth_token_id": "0",
				"protocol":      "0",
				"c2r_rtt":       "41",
			},
			Content: []byte{10, 20, 30, 40, 0x0D, 0x98},
		},
		waBinary.Node{
			Tag: "te2",
			Attrs: waBinary.Attrs{
				"relay_id":      "2",
				"relay_name":    "for2c02",
				"token_id":      "0",
				"auth_token_id": "0",
				"protocol":      "1",
				"c2r_rtt":       "43",
			},
			Content: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42, 0x0D, 0x98},
		},
	)
	relay.Content = relayChildren
	children[0] = relay
	node.Content = children

	relayData := ParseRelayDataFromCallAck(node)
	if relayData == nil {
		t.Fatalf("expected relay data from call offer ack")
	}
	if len(relayData.Endpoints) != 1 {
		t.Fatalf("expected merged endpoint for same relay id tuple, got %d", len(relayData.Endpoints))
	}
	if len(relayData.Endpoints[0].Addresses) < 2 {
		t.Fatalf("expected merged endpoint to retain multiple addresses, got %d", len(relayData.Endpoints[0].Addresses))
	}
	if relayData.Endpoints[0].C2RRTTMs == nil || *relayData.Endpoints[0].C2RRTTMs != 41 {
		t.Fatalf("expected merged endpoint to keep best c2r_rtt=41, got %+v", relayData.Endpoints[0].C2RRTTMs)
	}
}

func TestBuildRelayLatencyStanzasDedupeByRelayID(t *testing.T) {
	cli := &Client{}
	info := &types.CallInfo{
		CallID:      "call-latency-dedupe",
		PeerJID:     types.NewJID("155500001", types.DefaultUserServer),
		CallCreator: types.NewJID("155500000", types.DefaultUserServer),
	}
	relayData := &types.RelayData{
		Endpoints: []types.RelayEndpoint{
			{
				RelayID:   0,
				RelayName: "gru1c01",
				Addresses: []types.RelayAddress{
					{Protocol: 1, IPv4: "157.240.222.62", Port: 3480},
				},
			},
			{
				RelayID:   0,
				RelayName: "gru1c01",
				Addresses: []types.RelayAddress{
					{Protocol: 0, IPv4: "157.240.222.62", Port: 3480},
				},
			},
			{
				RelayID:   1,
				RelayName: "fbfh3c02",
				Addresses: []types.RelayAddress{
					{Protocol: 0, IPv4: "200.195.140.99", Port: 3480},
				},
			},
			{
				RelayID:   2,
				RelayName: "poa1c01",
				Addresses: []types.RelayAddress{
					{Protocol: 0, IPv4: "57.144.179.54", Port: 3480},
				},
			},
		},
	}

	stanzas := cli.BuildRelayLatencyStanzas(info, relayData)
	if len(stanzas) != 3 {
		t.Fatalf("expected one relaylatency stanza per relay id, got %d", len(stanzas))
	}
	for i, stanza := range stanzas {
		callChildren, ok := stanza.Content.([]waBinary.Node)
		if !ok || len(callChildren) == 0 {
			t.Fatalf("stanza %d missing call content", i)
		}
		rlChildren, ok := callChildren[0].Content.([]waBinary.Node)
		if !ok || len(rlChildren) == 0 {
			t.Fatalf("stanza %d missing relaylatency content", i)
		}
		var foundAddress bool
		for _, child := range rlChildren {
			if child.Tag != "te" {
				continue
			}
			if addr, ok := child.Content.([]byte); ok && len(addr) >= 6 {
				foundAddress = true
			}
		}
		if !foundAddress {
			t.Fatalf("stanza %d did not include relay address bytes", i)
		}
	}
}

func TestParseOfferAckDataIncludesEnrichment(t *testing.T) {
	ack := ParseOfferAckData(buildOfferAckNode("ack-enrich-1"))
	if ack == nil {
		t.Fatalf("expected parsed offer ack")
	}
	if ack.RelayData == nil {
		t.Fatalf("expected relay data in parsed offer ack")
	}
	if !ack.HasUploadFieldStat {
		t.Fatalf("expected uploadfieldstat in parsed offer ack")
	}
	if !ack.Joinable {
		t.Fatalf("expected joinable=true from relay attrs")
	}
	if len(ack.RTE) == 0 {
		t.Fatalf("expected rte payload from parsed offer ack")
	}
	if len(ack.VoIPSettingsByJID) != 1 {
		t.Fatalf("expected one voip_settings entry, got %d", len(ack.VoIPSettingsByJID))
	}
	if len(ack.UserDevices) != 1 {
		t.Fatalf("expected one user devices entry, got %d", len(ack.UserDevices))
	}
}

func TestParseRelayDataFromCallAckRejectsNonCallAck(t *testing.T) {
	node := buildOfferAckNode("ack-2")
	node.Attrs["class"] = "message"
	if got := ParseRelayDataFromCallAck(node); got != nil {
		t.Fatalf("expected nil relay data for non-call ack")
	}
}

func TestHandleCallAckEventStoresRelayAllocation(t *testing.T) {
	cli := &Client{}
	cm := NewCallManager(cli)
	cli.callManager = cm

	callID := "call-123"
	peer := types.NewJID("155500001", types.DefaultUserServer)
	cm.calls[callID] = &types.CallInfo{
		CallID:      callID,
		PeerJID:     peer,
		CallCreator: types.NewJID("155500000", types.DefaultUserServer),
		State:       types.CallStateRinging,
	}

	if err := cm.TrackOutgoingOffer(callID, "offer-stanza-1"); err != nil {
		t.Fatalf("TrackOutgoingOffer failed: %v", err)
	}

	cli.handleAckNode(context.Background(), buildOfferAckNode("offer-stanza-1"))

	info := cm.GetCall(callID)
	if info == nil {
		t.Fatalf("expected call info to exist")
	}
	if info.RelayData == nil {
		t.Fatalf("expected relay data to be stored from offer ack")
	}
	if info.RelayAllocatedAt.IsZero() {
		t.Fatalf("expected RelayAllocatedAt to be set")
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		_, transportState, snapshotOK := cm.GetCallStateSnapshot(callID)
		if !snapshotOK {
			t.Fatalf("expected call snapshot to exist while waiting for transport state")
		}
		if transportState == types.TransportStateFailed {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, transportState, snapshotOK := cm.GetCallStateSnapshot(callID)
	if !snapshotOK {
		t.Fatalf("expected call snapshot to exist after waiting for transport state")
	}
	if transportState != types.TransportStateFailed {
		t.Fatalf("expected failed transport state without configured transport, got %v", transportState)
	}

	cm.mu.RLock()
	info = cm.calls[callID]
	cm.mu.RUnlock()
	if info == nil {
		t.Fatalf("expected call info to still exist")
	}
	if info.OfferExtensions == nil || info.OfferExtensions.VoIPSettings == "" {
		t.Fatalf("expected ack voip_settings to be cached into call offer extensions")
	}
	if len(info.OfferAckVoIPByJID) != 1 {
		t.Fatalf("expected per-jid voip settings to be stored")
	}
	if len(info.OfferAckDevices) != 1 {
		t.Fatalf("expected ack user devices to be stored")
	}
	if len(cli.userDevicesCache) == 0 {
		t.Fatalf("expected ack user devices to update client device cache")
	}
}

func TestResolveCallIDByOfferStanzaID(t *testing.T) {
	cli := &Client{}
	cm := NewCallManager(cli)
	cli.callManager = cm

	callID := "call-abc"
	cm.calls[callID] = &types.CallInfo{
		CallID:      callID,
		PeerJID:     types.NewJID("155500001", types.DefaultUserServer),
		CallCreator: types.NewJID("155500000", types.DefaultUserServer),
	}
	if err := cm.TrackOutgoingOffer(callID, "offer-stanza-xyz"); err != nil {
		t.Fatalf("TrackOutgoingOffer failed: %v", err)
	}
	resolvedCallID, ok := cm.ResolveCallIDByOfferStanzaID("offer-stanza-xyz")
	if !ok {
		t.Fatalf("expected call id resolution to succeed")
	}
	if resolvedCallID != callID {
		t.Fatalf("unexpected resolved call id: got %s want %s", resolvedCallID, callID)
	}
}
