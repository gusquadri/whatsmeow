// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"reflect"
	"regexp"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

type testCallLIDSessionStore struct {
	store.NoopStore
	lidByPN    map[string]types.JID
	migrations [][2]types.JID
}

type testRelayAllocator struct {
	calls int
	relay *types.RelayData
	err   error
}

func (a *testRelayAllocator) AllocateRelayData(_ context.Context, _ *types.CallInfo) (*types.RelayData, error) {
	a.calls++
	return a.relay, a.err
}

type testOfferProfileProvider struct {
	calls    int
	profile  *types.CallOfferExtensions
	err      error
	lastInfo *types.CallInfo
}

func (p *testOfferProfileProvider) GetCallOfferExtensions(_ context.Context, info *types.CallInfo) (*types.CallOfferExtensions, error) {
	p.calls++
	p.lastInfo = info
	return p.profile, p.err
}

func (s *testCallLIDSessionStore) GetLIDForPN(_ context.Context, pn types.JID) (types.JID, error) {
	if s.lidByPN == nil {
		return types.EmptyJID, nil
	}
	if mapped, ok := s.lidByPN[pn.User]; ok {
		out := mapped
		out.Device = pn.Device
		return out, nil
	}
	return types.EmptyJID, nil
}

func (s *testCallLIDSessionStore) MigratePNToLID(_ context.Context, pn, lid types.JID) error {
	s.migrations = append(s.migrations, [2]types.JID{pn, lid})
	return nil
}

func TestSignalingTypeResponseType(t *testing.T) {
	tests := []struct {
		name string
		st   types.SignalingType
		want types.ResponseType
	}{
		{name: "offer receipt", st: types.SignalingOffer, want: types.ResponseTypeReceipt},
		{name: "accept receipt", st: types.SignalingAccept, want: types.ResponseTypeReceipt},
		{name: "reject receipt", st: types.SignalingReject, want: types.ResponseTypeReceipt},
		{name: "enc rekey receipt", st: types.SignalingEncRekey, want: types.ResponseTypeReceipt},
		{name: "offer notice ack", st: types.SignalingOfferNotice, want: types.ResponseTypeAck},
		{name: "transport ack", st: types.SignalingTransport, want: types.ResponseTypeAck},
		{name: "none has no response", st: types.SignalingNone, want: types.ResponseTypeNone},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.st.GetResponseType()
			if got != tc.want {
				t.Fatalf("unexpected response type for %v: got %v want %v", tc.st, got, tc.want)
			}
		})
	}
}

func TestParseCallStanzaFindsSignalingChild(t *testing.T) {
	from := types.NewJID("15550001", types.DefaultUserServer)
	creator := types.NewJID("15550002", types.DefaultUserServer)

	node := &waBinary.Node{
		Tag: "call",
		Attrs: waBinary.Attrs{
			"id":   "stanza-1",
			"from": from,
			"t":    "1",
		},
		Content: []waBinary.Node{
			{Tag: "not_signaling"},
			{
				Tag: "offer",
				Attrs: waBinary.Attrs{
					"call-id":      "call-1",
					"call-creator": creator,
				},
			},
		},
	}

	parsed, err := ParseCallStanza(node)
	if err != nil {
		t.Fatalf("ParseCallStanza returned error: %v", err)
	}
	if parsed.SignalingType != types.SignalingOffer {
		t.Fatalf("unexpected signaling type: got %v want %v", parsed.SignalingType, types.SignalingOffer)
	}
	if parsed.CallID != "call-1" {
		t.Fatalf("unexpected call id: got %q want %q", parsed.CallID, "call-1")
	}
}

func TestParseCallStanzaErrorsWithoutSignalingChild(t *testing.T) {
	node := &waBinary.Node{
		Tag: "call",
		Attrs: waBinary.Attrs{
			"id": "stanza-1",
			"t":  "1",
		},
		Content: []waBinary.Node{
			{Tag: "not_signaling"},
		},
	}
	_, err := ParseCallStanza(node)
	if err == nil {
		t.Fatalf("expected ParseCallStanza to fail when signaling child is missing")
	}
}

func TestParseRelayDataDecodesBase64AndStringContent(t *testing.T) {
	from := types.NewJID("15550001", types.DefaultUserServer)
	creator := types.NewJID("15550002", types.DefaultUserServer)

	hbhRaw := bytes.Repeat([]byte{0xAB}, 30)
	relayKeyRaw := bytes.Repeat([]byte{0xCD}, 16)
	relayAddr := []byte{1, 2, 3, 4, 0x0D, 0x98} // 1.2.3.4:3480

	node := &waBinary.Node{
		Tag: "call",
		Attrs: waBinary.Attrs{
			"id":   "stanza-1",
			"from": from,
			"t":    "1",
		},
		Content: []waBinary.Node{{
			Tag: "offer",
			Attrs: waBinary.Attrs{
				"call-id":      "call-1",
				"call-creator": creator,
			},
			Content: []waBinary.Node{{
				Tag: "relay",
				Attrs: waBinary.Attrs{
					"uuid":     "relay-uuid",
					"self_pid": "1",
					"peer_pid": "2",
				},
				Content: []waBinary.Node{
					{Tag: "hbh_key", Content: `"` + base64.StdEncoding.EncodeToString(hbhRaw) + `"`},
					{Tag: "key", Content: `"` + base64.StdEncoding.EncodeToString(relayKeyRaw) + `"`},
					{Tag: "token", Attrs: waBinary.Attrs{"id": "0"}, Content: "token-as-string"},
					{Tag: "auth_token", Attrs: waBinary.Attrs{"id": "0"}, Content: []byte("auth-token-bytes")},
					{
						Tag: "te2",
						Attrs: waBinary.Attrs{
							"relay_id":      "7",
							"relay_name":    "example-relay",
							"token_id":      "0",
							"auth_token_id": "0",
						},
						Content: relayAddr,
					},
				},
			}},
		}},
	}

	parsed, err := ParseCallStanza(node)
	if err != nil {
		t.Fatalf("ParseCallStanza returned error: %v", err)
	}
	if parsed.RelayData == nil {
		t.Fatalf("expected relay data to be parsed")
	}
	if !bytes.Equal(parsed.RelayData.HBHKey, hbhRaw) {
		t.Fatalf("unexpected hbh key bytes")
	}
	if !bytes.Equal(parsed.RelayData.RelayKey, relayKeyRaw) {
		t.Fatalf("unexpected relay key bytes")
	}
	if len(parsed.RelayData.RelayTokens) != 1 || !bytes.Equal(parsed.RelayData.RelayTokens[0], []byte("token-as-string")) {
		t.Fatalf("unexpected relay token parsing")
	}
	if len(parsed.RelayData.AuthTokens) != 1 || !bytes.Equal(parsed.RelayData.AuthTokens[0], []byte("auth-token-bytes")) {
		t.Fatalf("unexpected auth token parsing")
	}
	if len(parsed.RelayData.Endpoints) != 1 {
		t.Fatalf("expected one relay endpoint, got %d", len(parsed.RelayData.Endpoints))
	}
}

func TestParseEncRekeyAcceptsStringContent(t *testing.T) {
	from := types.NewJID("15550001", types.DefaultUserServer)
	creator := types.NewJID("15550002", types.DefaultUserServer)
	ciphertextRaw := []byte{0x01, 0x02, 0x03, 0x04}

	node := &waBinary.Node{
		Tag: "call",
		Attrs: waBinary.Attrs{
			"id":   "stanza-1",
			"from": from,
			"t":    "1",
		},
		Content: []waBinary.Node{{
			Tag: "enc_rekey",
			Attrs: waBinary.Attrs{
				"call-id":      "call-1",
				"call-creator": creator,
			},
			Content: []waBinary.Node{
				{
					Tag:     "enc",
					Attrs:   waBinary.Attrs{"type": "msg", "count": "4"},
					Content: base64.StdEncoding.EncodeToString(ciphertextRaw),
				},
			},
		}},
	}

	parsed, err := ParseCallStanza(node)
	if err != nil {
		t.Fatalf("ParseCallStanza returned error: %v", err)
	}
	if parsed.OfferEncData == nil {
		t.Fatalf("expected enc_rekey data to be parsed")
	}
	if !bytes.Equal(parsed.OfferEncData.Ciphertext, ciphertextRaw) {
		t.Fatalf("unexpected ciphertext bytes")
	}
	if parsed.EncRekeyData == nil {
		t.Fatalf("expected explicit enc_rekey data to be parsed")
	}
	if parsed.EncRekeyData.Count != 4 {
		t.Fatalf("unexpected enc_rekey count: got %d want 4", parsed.EncRekeyData.Count)
	}
	if parsed.OfferEncData.Version != 4 {
		t.Fatalf("expected compatibility version value to mirror rekey count, got %d", parsed.OfferEncData.Version)
	}
}

func TestParseTransportPayloadAndCallerUsername(t *testing.T) {
	from := types.NewJID("15550001", types.DefaultUserServer)
	creator := types.NewJID("15550002", types.DefaultUserServer)
	payload := []byte{0x01, 0x02, 0x03}

	node := &waBinary.Node{
		Tag: "call",
		Attrs: waBinary.Attrs{
			"id":   "stanza-transport",
			"from": from,
			"t":    "1",
		},
		Content: []waBinary.Node{{
			Tag: "transport",
			Attrs: waBinary.Attrs{
				"call-id":      "call-transport-1",
				"call-creator": creator,
				"username":     "caller-name",
			},
			Content: payload,
		}},
	}

	parsed, err := ParseCallStanza(node)
	if err != nil {
		t.Fatalf("ParseCallStanza returned error: %v", err)
	}
	if parsed.CallerUser != "caller-name" {
		t.Fatalf("unexpected caller username: got %q want %q", parsed.CallerUser, "caller-name")
	}
	if !bytes.Equal(parsed.Payload, payload) {
		t.Fatalf("unexpected parsed transport payload")
	}
	if parsed.TransportData == nil {
		t.Fatalf("expected parsed transport data")
	}
	if !bytes.Equal(parsed.TransportData.RawData, payload) {
		t.Fatalf("unexpected parsed raw transport data")
	}
}

func TestParseTransportPayloadJSONData(t *testing.T) {
	from := types.NewJID("15550001", types.DefaultUserServer)
	creator := types.NewJID("15550002", types.DefaultUserServer)
	payload := []byte(`{"ufrag":"abc","pwd":"xyz","candidates":[{"candidate":"candidate:1","sdp_mid":"0","sdp_m_line_index":1}]}`)

	node := &waBinary.Node{
		Tag: "call",
		Attrs: waBinary.Attrs{
			"id":   "stanza-transport-json",
			"from": from,
			"t":    "1",
		},
		Content: []waBinary.Node{{
			Tag: "transport",
			Attrs: waBinary.Attrs{
				"call-id":      "call-transport-2",
				"call-creator": creator,
			},
			Content: payload,
		}},
	}

	parsed, err := ParseCallStanza(node)
	if err != nil {
		t.Fatalf("ParseCallStanza returned error: %v", err)
	}
	if parsed.TransportData == nil {
		t.Fatalf("expected parsed transport data")
	}
	if parsed.TransportData.Ufrag != "abc" || parsed.TransportData.Pwd != "xyz" {
		t.Fatalf("unexpected parsed transport credentials: %+v", parsed.TransportData)
	}
	if len(parsed.TransportData.Candidates) != 1 {
		t.Fatalf("unexpected parsed transport candidates: %+v", parsed.TransportData.Candidates)
	}
}

func TestParseRelayLatencyIncludesAddressAndRawValue(t *testing.T) {
	from := types.NewJID("15550001", types.DefaultUserServer)
	creator := types.NewJID("15550002", types.DefaultUserServer)
	address := []byte{1, 2, 3, 4, 0x0D, 0x98} // 1.2.3.4:3480
	rawLatency := uint32(0x0200002A)          // 42ms in lower 24 bits

	node := &waBinary.Node{
		Tag: "call",
		Attrs: waBinary.Attrs{
			"id":   "stanza-relay-latency",
			"from": from,
			"t":    "1",
		},
		Content: []waBinary.Node{{
			Tag: "relaylatency",
			Attrs: waBinary.Attrs{
				"call-id":      "call-relay-1",
				"call-creator": creator,
			},
			Content: []waBinary.Node{{
				Tag: "te",
				Attrs: waBinary.Attrs{
					"relay_id":   "7",
					"relay_name": "example-relay",
					"latency":    "33554474", // 0x0200002A
				},
				Content: address,
			}},
		}},
	}

	parsed, err := ParseCallStanza(node)
	if err != nil {
		t.Fatalf("ParseCallStanza returned error: %v", err)
	}
	if len(parsed.RelayLatency) != 1 {
		t.Fatalf("expected one relay latency item, got %d", len(parsed.RelayLatency))
	}
	got := parsed.RelayLatency[0]
	if got.RelayID != 7 || got.RelayName != "example-relay" {
		t.Fatalf("unexpected relay metadata: %+v", got)
	}
	if got.RawLatency != rawLatency || got.LatencyMs != 42 {
		t.Fatalf("unexpected latency parsing: %+v", got)
	}
	if got.IPv4 != "1.2.3.4" || got.Port != 3480 {
		t.Fatalf("unexpected relay address parsing: %+v", got)
	}
}

func TestBuildRelayLatencyStanzaUsesC2RRTTAndAddressFallbacks(t *testing.T) {
	own := types.NewJID("15550001", types.DefaultUserServer)
	peer := types.NewJID("15550002", types.DefaultUserServer)
	cli := &Client{Store: &store.Device{ID: &own}}

	fastRTT := uint32(42)
	info := &types.CallInfo{
		CallID:      "call-relay-out-1",
		PeerJID:     peer,
		CallCreator: own,
	}
	relayData := &types.RelayData{
		Endpoints: []types.RelayEndpoint{
			{
				RelayName: "relay-fast",
				C2RRTTMs:  &fastRTT,
				Addresses: []types.RelayAddress{
					{Protocol: 0, IPv4: "1.2.3.4", Port: 0},
				},
			},
			{
				RelayName: "relay-fallback",
				Addresses: []types.RelayAddress{
					{Protocol: 0, IPv4: "5.6.7.8", Port: 4000},
				},
			},
		},
	}

	node := cli.BuildRelayLatencyStanza(info, relayData)
	callChildren, ok := node.Content.([]waBinary.Node)
	if !ok || len(callChildren) != 1 {
		t.Fatalf("expected single relaylatency child")
	}
	relayLatency := callChildren[0]
	teChildren, ok := relayLatency.Content.([]waBinary.Node)
	if !ok || len(teChildren) != 2 {
		t.Fatalf("expected two te children, got %#v", relayLatency.Content)
	}

	firstLatency, _ := teChildren[0].Attrs["latency"].(string)
	if firstLatency != "33554474" {
		t.Fatalf("unexpected encoded c2r_rtt latency: got %s want 33554474", firstLatency)
	}
	secondLatency, _ := teChildren[1].Attrs["latency"].(string)
	if secondLatency != "33554482" {
		t.Fatalf("unexpected fallback latency: got %s want 33554482", secondLatency)
	}

	firstAddr, ok := teChildren[0].Content.([]byte)
	if !ok || len(firstAddr) != 6 {
		t.Fatalf("expected first te to include 6-byte address payload")
	}
	if !bytes.Equal(firstAddr[:4], []byte{1, 2, 3, 4}) {
		t.Fatalf("unexpected first te ip bytes: %v", firstAddr[:4])
	}
	if port := binary.BigEndian.Uint16(firstAddr[4:]); port != defaultRelayPort {
		t.Fatalf("unexpected first te port fallback: got %d want %d", port, defaultRelayPort)
	}
}

func TestBuildRelayLatencyStanzaIncludesDestinationFromOfferAckDevices(t *testing.T) {
	own := types.NewJID("15550001", types.DefaultUserServer)
	peer := types.NewJID("15550002", types.HiddenUserServer)
	deviceA := types.NewJID("15550002:7", types.HiddenUserServer)
	deviceB := types.NewJID("15550002:8", types.HiddenUserServer)
	cli := &Client{Store: &store.Device{ID: &own}}

	info := &types.CallInfo{
		CallID:      "call-relay-out-destination-1",
		PeerJID:     peer,
		CallCreator: own,
		OfferAckDevices: map[types.JID][]types.JID{
			peer: {deviceB, deviceA},
		},
	}
	relayData := &types.RelayData{
		Endpoints: []types.RelayEndpoint{
			{
				RelayName: "relay-fast",
				Addresses: []types.RelayAddress{
					{Protocol: 0, IPv4: "1.2.3.4", Port: defaultRelayPort},
				},
			},
		},
	}

	node := cli.BuildRelayLatencyStanza(info, relayData)
	callChildren, ok := node.Content.([]waBinary.Node)
	if !ok || len(callChildren) != 1 {
		t.Fatalf("expected single relaylatency child")
	}
	relayLatency := callChildren[0]
	relayChildren, ok := relayLatency.Content.([]waBinary.Node)
	if !ok || len(relayChildren) < 2 {
		t.Fatalf("expected te + destination children, got %#v", relayLatency.Content)
	}
	destination := relayChildren[len(relayChildren)-1]
	if destination.Tag != "destination" {
		t.Fatalf("expected destination child, got %s", destination.Tag)
	}
	toChildren, ok := destination.Content.([]waBinary.Node)
	if !ok || len(toChildren) != 2 {
		t.Fatalf("expected two destination to children, got %#v", destination.Content)
	}
	got := map[types.JID]bool{}
	for _, toNode := range toChildren {
		jid, _ := toNode.Attrs["jid"].(types.JID)
		got[jid.ToNonAD()] = true
	}
	if !got[deviceA.ToNonAD()] || !got[deviceB.ToNonAD()] {
		t.Fatalf("missing destination device fanout: got=%v", got)
	}
}

func TestBuildTerminateStanzaIncludesDestinationFromOfferAckDevices(t *testing.T) {
	own := types.NewJID("15550001", types.DefaultUserServer)
	peer := types.NewJID("15550002", types.HiddenUserServer)
	device := types.NewJID("15550002:7", types.HiddenUserServer)
	cli := &Client{Store: &store.Device{ID: &own}}

	info := &types.CallInfo{
		CallID:      "call-terminate-destination-1",
		PeerJID:     peer,
		CallCreator: own,
		OfferAckDevices: map[types.JID][]types.JID{
			peer: {device},
		},
	}

	node := cli.BuildTerminateStanza(info)
	callChildren, ok := node.Content.([]waBinary.Node)
	if !ok || len(callChildren) != 1 {
		t.Fatalf("expected single terminate child")
	}
	terminate := callChildren[0]
	terminateChildren, ok := terminate.Content.([]waBinary.Node)
	if !ok || len(terminateChildren) != 1 {
		t.Fatalf("expected destination under terminate, got %#v", terminate.Content)
	}
	if terminateChildren[0].Tag != "destination" {
		t.Fatalf("expected destination child under terminate, got %s", terminateChildren[0].Tag)
	}
}

func TestGetOwnIDForCallPeerPrefersCorrectIdentity(t *testing.T) {
	pn := types.NewJID("15550001", types.DefaultUserServer)
	lid := types.NewJID("123456789", types.HiddenUserServer)
	cli := &Client{Store: &store.Device{ID: &pn, LID: lid}}

	tests := []struct {
		name string
		peer types.JID
		want types.JID
	}{
		{
			name: "pn peer uses own pn",
			peer: types.NewJID("15550099", types.DefaultUserServer),
			want: pn.ToNonAD(),
		},
		{
			name: "lid peer uses own lid",
			peer: types.NewJID("123456700", types.HiddenUserServer),
			want: lid.ToNonAD(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cli.getOwnIDForCallPeer(tc.peer)
			if got != tc.want {
				t.Fatalf("unexpected own id: got %s want %s", got, tc.want)
			}
		})
	}
}

func TestGetOwnIDForCallPeerUsesOwnDeviceForLIDWhenMissing(t *testing.T) {
	pn := types.NewJID("15550001", types.DefaultUserServer)
	pn.Device = 8
	lid := types.NewJID("123456789", types.HiddenUserServer) // no device set in store
	cli := &Client{Store: &store.Device{ID: &pn, LID: lid}}

	got := cli.getOwnIDForCallPeer(types.NewJID("99887766", types.HiddenUserServer))
	if got.Server != types.HiddenUserServer || got.User != lid.User || got.Device != pn.Device {
		t.Fatalf("unexpected own id for LID peer: got %s", got)
	}
}

func TestGenerateCallKeyReturnsKeyWithoutPanic(t *testing.T) {
	key, err := GenerateCallKey()
	if err != nil {
		t.Fatalf("GenerateCallKey returned error: %v", err)
	}
	if key.Generation != 1 {
		t.Fatalf("unexpected generation: got %d want 1", key.Generation)
	}
}

func TestCallManagerStartCallGeneratesUpperHexCallID(t *testing.T) {
	own := types.NewJID("15550001", types.DefaultUserServer)
	peer := types.NewJID("15550002", types.DefaultUserServer)
	cli := &Client{Store: &store.Device{ID: &own}}
	cm := NewCallManager(cli)

	info, _, err := cm.StartCall(context.Background(), peer, types.CallOptions{})
	if err != nil {
		t.Fatalf("StartCall returned error: %v", err)
	}
	if ok, matchErr := regexp.MatchString("^[A-F0-9]{32}$", info.CallID); matchErr != nil {
		t.Fatalf("failed to validate call id format: %v", matchErr)
	} else if !ok {
		t.Fatalf("unexpected call id format: %q", info.CallID)
	}
}

func TestCallManagerStartCallResolvesPeerPNToLIDForSignaling(t *testing.T) {
	ownPN := types.NewJID("15550001", types.DefaultUserServer)
	ownLID := types.NewJID("9988776655", types.HiddenUserServer)
	peerPN := types.NewJID("15550002", types.DefaultUserServer)
	peerLID := types.NewJID("1122334455", types.HiddenUserServer)

	testStore := &testCallLIDSessionStore{
		lidByPN: map[string]types.JID{
			peerPN.User: peerLID,
		},
	}
	cli := &Client{
		Store: &store.Device{
			ID:       &ownPN,
			LID:      ownLID,
			Sessions: testStore,
			LIDs:     testStore,
		},
	}
	cm := NewCallManager(cli)

	info, _, err := cm.StartCall(context.Background(), peerPN, types.CallOptions{})
	if err != nil {
		t.Fatalf("StartCall returned error: %v", err)
	}
	if info.PeerJID != peerLID.ToNonAD() {
		t.Fatalf("unexpected signaling peer jid: got %s want %s", info.PeerJID, peerLID.ToNonAD())
	}
	if info.CallCreator != ownLID.ToNonAD() {
		t.Fatalf("unexpected call creator identity: got %s want %s", info.CallCreator, ownLID.ToNonAD())
	}
	if len(testStore.migrations) != 1 {
		t.Fatalf("expected one session migration, got %d", len(testStore.migrations))
	}
	if !reflect.DeepEqual(testStore.migrations[0], [2]types.JID{peerPN.ToNonAD(), peerLID.ToNonAD()}) {
		t.Fatalf("unexpected migration pair: %+v", testStore.migrations[0])
	}
}

func TestDefaultCallOfferCountryCodeFromClientPayloadLocale(t *testing.T) {
	orig := store.BaseClientPayload.GetUserAgent().GetLocaleCountryIso31661Alpha2()
	store.BaseClientPayload.UserAgent.LocaleCountryIso31661Alpha2 = proto.String("br")
	t.Cleanup(func() {
		store.BaseClientPayload.UserAgent.LocaleCountryIso31661Alpha2 = proto.String(orig)
	})

	own := types.NewJID("15550001", types.DefaultUserServer)
	cli := &Client{Store: &store.Device{ID: &own}}
	if got := cli.defaultCallOfferCountryCode(); got != "BR" {
		t.Fatalf("unexpected default caller_country_code: got %q want BR", got)
	}
}

func TestCallManagerStartCallDoesNotReuseCachedAckOfferProfileByDefault(t *testing.T) {
	own := types.NewJID("15550001", types.DefaultUserServer)
	peer := types.NewJID("15550002", types.HiddenUserServer)
	cli := &Client{Store: &store.Device{ID: &own}}
	cm := NewCallManager(cli)

	offerProfile := &types.CallOfferExtensions{
		Joinable:        true,
		UploadFieldStat: true,
		Capability:      []byte{0x01, 0x05, 0xFF, 0x09, 0xE4, 0xFA, 0x13},
		VoIPSettings:    `{"options":{"disable_p2p":"1","enable_ssrc_demux":"1"}}`,
	}
	_, err := cm.RegisterIncomingCall(&ParsedCallStanza{
		CallID:          "incoming-call-profile",
		From:            peer,
		CallCreator:     peer,
		OfferExtensions: offerProfile,
	})
	if err != nil {
		t.Fatalf("RegisterIncomingCall returned error: %v", err)
	}

	outgoing, _, err := cm.StartCall(context.Background(), peer, types.CallOptions{})
	if err != nil {
		t.Fatalf("StartCall returned error: %v", err)
	}
	if outgoing.OfferExtensions == nil {
		t.Fatalf("expected outgoing offer extensions")
	}
	if !bytes.Equal(outgoing.OfferExtensions.Capability, defaultCapability) {
		t.Fatalf("expected default waweb capability for new outgoing offer, got %x", outgoing.OfferExtensions.Capability)
	}
	if outgoing.OfferExtensions.VoIPSettings != "" {
		t.Fatalf("expected no cached voip_settings reuse in outbound default offer")
	}
	if outgoing.OfferExtensions.Joinable {
		t.Fatalf("expected joinable to stay unset by default")
	}
	if outgoing.OfferExtensions.UploadFieldStat {
		t.Fatalf("expected uploadfieldstat to stay unset by default")
	}
	if outgoing.OfferExtensions.CallerCountryCode != "" {
		t.Fatalf("caller_country_code should not be auto-filled by default")
	}
}

func TestCallManagerStartCallUsesOfferProfileProviderWhenNoExplicitProfile(t *testing.T) {
	own := types.NewJID("15550001", types.DefaultUserServer)
	peer := types.NewJID("15550002", types.HiddenUserServer)
	cli := &Client{Store: &store.Device{ID: &own}}
	cm := NewCallManager(cli)

	provider := &testOfferProfileProvider{
		profile: &types.CallOfferExtensions{
			Joinable:          true,
			UploadFieldStat:   true,
			CallerCountryCode: "BR",
			Capability:        []byte{0x01, 0x05, 0xFF, 0x09, 0xE4, 0xFA, 0x13},
			VoIPSettings:      `{"options":{"disable_p2p":"1"}}`,
		},
	}
	cm.SetOfferProfileProvider(provider)

	outgoing, _, err := cm.StartCall(context.Background(), peer, types.CallOptions{})
	if err != nil {
		t.Fatalf("StartCall returned error: %v", err)
	}
	if provider.calls != 1 {
		t.Fatalf("expected offer profile provider to be called once, got %d", provider.calls)
	}
	if provider.lastInfo == nil || provider.lastInfo.CallID == "" || provider.lastInfo.PeerJID != peer.ToNonAD() {
		t.Fatalf("unexpected provider call context: %+v", provider.lastInfo)
	}
	if outgoing.OfferExtensions == nil {
		t.Fatalf("expected outgoing offer extensions")
	}
	if outgoing.OfferExtensions.VoIPSettings != provider.profile.VoIPSettings {
		t.Fatalf("expected provider voip_settings to be used")
	}
	if !bytes.Equal(outgoing.OfferExtensions.Capability, provider.profile.Capability) {
		t.Fatalf("expected provider capability to be used")
	}
	if outgoing.OfferExtensions.CallerCountryCode != "BR" {
		t.Fatalf("expected provider caller country code to be used, got %q", outgoing.OfferExtensions.CallerCountryCode)
	}
}

func TestCallManagerStartCallReturnsProviderError(t *testing.T) {
	own := types.NewJID("15550001", types.DefaultUserServer)
	peer := types.NewJID("15550002", types.HiddenUserServer)
	cli := &Client{Store: &store.Device{ID: &own}}
	cm := NewCallManager(cli)

	provider := &testOfferProfileProvider{err: errors.New("provider boom")}
	cm.SetOfferProfileProvider(provider)

	_, _, err := cm.StartCall(context.Background(), peer, types.CallOptions{})
	if err == nil {
		t.Fatalf("expected StartCall to fail when provider fails")
	}
}

func TestCallManagerStartCallDoesNotReuseCachedIncomingProfileAcrossPeers(t *testing.T) {
	own := types.NewJID("15550001", types.DefaultUserServer)
	peerIncoming := types.NewJID("15550002", types.HiddenUserServer)
	peerB := types.NewJID("15550003", types.HiddenUserServer)
	peerC := types.NewJID("15550004", types.HiddenUserServer)
	cli := &Client{Store: &store.Device{ID: &own}}
	cm := NewCallManager(cli)

	incomingProfile := &types.CallOfferExtensions{
		Joinable:        true,
		UploadFieldStat: true,
		Capability:      []byte{0x01, 0x05, 0xFF, 0x09, 0xE4, 0xFA, 0x13},
		VoIPSettings:    `{"options":{"enable_ssrc_demux":"1"}}`,
	}
	_, err := cm.RegisterIncomingCall(&ParsedCallStanza{
		CallID:          "incoming-call-profile-cache",
		From:            peerIncoming,
		CallCreator:     peerIncoming,
		OfferExtensions: incomingProfile,
	})
	if err != nil {
		t.Fatalf("RegisterIncomingCall returned error: %v", err)
	}

	outgoingB, _, err := cm.StartCall(context.Background(), peerB, types.CallOptions{})
	if err != nil {
		t.Fatalf("StartCall peerB returned error: %v", err)
	}
	if outgoingB.OfferExtensions == nil {
		t.Fatalf("expected outgoing peerB offer extensions")
	}
	if outgoingB.OfferExtensions.VoIPSettings != "" {
		t.Fatalf("expected outgoing peerB to NOT reuse cached incoming voip_settings")
	}
	if outgoingB.OfferExtensions.Joinable || outgoingB.OfferExtensions.UploadFieldStat {
		t.Fatalf("expected outgoing peerB to keep joinable/uploadfieldstat unset by default")
	}

	outgoingC, _, err := cm.StartCall(context.Background(), peerC, types.CallOptions{})
	if err != nil {
		t.Fatalf("StartCall peerC returned error: %v", err)
	}
	if outgoingC.OfferExtensions == nil {
		t.Fatalf("expected outgoing peerC offer extensions")
	}
	if outgoingC.OfferExtensions.VoIPSettings != "" {
		t.Fatalf("expected outgoing peerC to NOT reuse cached incoming voip_settings")
	}
}

func TestCallManagerStartCallDoesNotReuseCachedRTEByDefault(t *testing.T) {
	own := types.NewJID("15550001", types.DefaultUserServer)
	peerIncoming := types.NewJID("15550002", types.HiddenUserServer)
	peerOutgoing := types.NewJID("15550003", types.HiddenUserServer)
	cli := &Client{Store: &store.Device{ID: &own}}
	cm := NewCallManager(cli)

	_, err := cm.RegisterIncomingCall(&ParsedCallStanza{
		CallID:      "incoming-call-rte",
		From:        peerIncoming,
		CallCreator: peerIncoming,
		OfferExtensions: &types.CallOfferExtensions{
			Joinable:        true,
			UploadFieldStat: true,
			RTE:             []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		},
	})
	if err != nil {
		t.Fatalf("RegisterIncomingCall returned error: %v", err)
	}

	outgoing, _, err := cm.StartCall(context.Background(), peerOutgoing, types.CallOptions{})
	if err != nil {
		t.Fatalf("StartCall returned error: %v", err)
	}
	if outgoing.OfferExtensions == nil {
		t.Fatalf("expected outgoing offer extensions")
	}
	if len(outgoing.OfferExtensions.RTE) != 0 {
		t.Fatalf("expected outgoing offer extension RTE to be empty by default, got %x", outgoing.OfferExtensions.RTE)
	}
}

func TestCallManagerStartCallUsesRelayAllocatorWhenNoCachedRelay(t *testing.T) {
	own := types.NewJID("15550001", types.DefaultUserServer)
	peer := types.NewJID("15550002", types.HiddenUserServer)
	cli := &Client{Store: &store.Device{ID: &own}}
	cm := NewCallManager(cli)

	allocator := &testRelayAllocator{
		relay: &types.RelayData{
			AuthTokens: [][]byte{{0xAA, 0xBB}},
			Endpoints: []types.RelayEndpoint{{
				RelayID:     1,
				RelayName:   "allocator-relay",
				TokenID:     0,
				AuthTokenID: 0,
				Addresses:   []types.RelayAddress{{Protocol: 0, IPv4: "1.2.3.4", Port: 3480}},
			}},
		},
	}
	cm.SetRelayAllocator(allocator)

	outgoing, _, err := cm.StartCall(context.Background(), peer, types.CallOptions{})
	if err != nil {
		t.Fatalf("StartCall returned error: %v", err)
	}
	if allocator.calls != 1 {
		t.Fatalf("expected relay allocator to be called once, got %d", allocator.calls)
	}
	if outgoing.RelayData == nil || len(outgoing.RelayData.AuthTokens) != 1 {
		t.Fatalf("expected relay data from allocator")
	}
}

func TestCallManagerStartCallDoesNotUseStaleRelayDataFromPreviousCall(t *testing.T) {
	own := types.NewJID("15550001", types.DefaultUserServer)
	peer := types.NewJID("15550002", types.HiddenUserServer)
	cli := &Client{Store: &store.Device{ID: &own}}
	cm := NewCallManager(cli)

	// Simulate a previous call that populated the relay cache.
	_, err := cm.RegisterIncomingCall(&ParsedCallStanza{
		CallID:      "incoming-call",
		From:        peer,
		CallCreator: peer,
		RelayData: &types.RelayData{
			AuthTokens: [][]byte{{0x09, 0x03, 0x68, 0x0b}},
			Endpoints: []types.RelayEndpoint{{
				RelayID:     1,
				RelayName:   "relay-a",
				TokenID:     0,
				AuthTokenID: 0,
				Addresses:   []types.RelayAddress{{Protocol: 0, IPv4: "1.2.3.4", Port: 3480}},
			}},
		},
	})
	if err != nil {
		t.Fatalf("RegisterIncomingCall returned error: %v", err)
	}

	// StartCall for a second call to same peer must NOT pre-populate relay data
	// from the cache. WAWeb never sends <relay> in the outgoing offer — relay is
	// server-allocated and returned in the offer ACK. Using stale relay data
	// (expired auth tokens/UUID) breaks the second call.
	outgoing, _, err := cm.StartCall(context.Background(), peer, types.CallOptions{})
	if err != nil {
		t.Fatalf("StartCall returned error: %v", err)
	}
	if outgoing.RelayData != nil {
		t.Fatalf("expected outgoing offer to have no relay data (server allocates relay), got %+v", outgoing.RelayData)
	}
}

func TestCallManagerStartCallUsesOptionRelayDataOverCache(t *testing.T) {
	own := types.NewJID("15550001", types.DefaultUserServer)
	peer := types.NewJID("15550002", types.HiddenUserServer)
	cli := &Client{Store: &store.Device{ID: &own}}
	cm := NewCallManager(cli)

	_, err := cm.RegisterIncomingCall(&ParsedCallStanza{
		CallID:      "incoming-call-cache",
		From:        peer,
		CallCreator: peer,
		RelayData: &types.RelayData{
			AuthTokens: [][]byte{{0x01}},
		},
	})
	if err != nil {
		t.Fatalf("RegisterIncomingCall returned error: %v", err)
	}

	optionRelay := &types.RelayData{
		AuthTokens: [][]byte{{0xAA, 0xBB}},
	}
	outgoing, _, err := cm.StartCall(context.Background(), peer, types.CallOptions{
		RelayData: optionRelay,
	})
	if err != nil {
		t.Fatalf("StartCall returned error: %v", err)
	}
	if outgoing.RelayData == nil || len(outgoing.RelayData.AuthTokens) != 1 {
		t.Fatalf("expected option relay data in outgoing call")
	}
	if !bytes.Equal(outgoing.RelayData.AuthTokens[0], optionRelay.AuthTokens[0]) {
		t.Fatalf("expected option relay data to be used, got %x", outgoing.RelayData.AuthTokens[0])
	}
	if &outgoing.RelayData.AuthTokens[0][0] == &optionRelay.AuthTokens[0][0] {
		t.Fatalf("expected cloned option relay auth token bytes, got shared slice")
	}
}

func TestCallManagerStartCallDoesNotUseLastKnownRelayDataAcrossPeers(t *testing.T) {
	own := types.NewJID("15550001", types.DefaultUserServer)
	peerA := types.NewJID("15550002", types.HiddenUserServer)
	peerB := types.NewJID("15550003", types.HiddenUserServer)
	cli := &Client{Store: &store.Device{ID: &own}}
	cm := NewCallManager(cli)

	_, err := cm.RegisterIncomingCall(&ParsedCallStanza{
		CallID:      "incoming-call-global-relay",
		From:        peerA,
		CallCreator: peerA,
		RelayData: &types.RelayData{
			AuthTokens: [][]byte{{0x10, 0x20}},
		},
	})
	if err != nil {
		t.Fatalf("RegisterIncomingCall returned error: %v", err)
	}

	// Outgoing call to a different peer must not carry relay leftovers from peerA's call.
	outgoing, _, err := cm.StartCall(context.Background(), peerB, types.CallOptions{})
	if err != nil {
		t.Fatalf("StartCall returned error: %v", err)
	}
	if outgoing.RelayData != nil {
		t.Fatalf("expected outgoing offer to have no relay data (server allocates relay), got %+v", outgoing.RelayData)
	}
}

func TestCallAttrStringSupportsMessageID(t *testing.T) {
	if got := callAttrString(types.MessageID("3EB0ABCDEF")); got != "3EB0ABCDEF" {
		t.Fatalf("unexpected message id conversion: %q", got)
	}
	if got := callAttrString("plain-id"); got != "plain-id" {
		t.Fatalf("unexpected string conversion: %q", got)
	}
}

func TestBuildOfferStanzaOmitsFromAndUsesCallCreator(t *testing.T) {
	own := types.NewJID("15550001", types.DefaultUserServer)
	creator := types.NewJID("99887766", types.HiddenUserServer)
	peer := types.NewJID("15550002", types.DefaultUserServer)
	cli := &Client{Store: &store.Device{ID: &own, LID: creator}}

	info := &types.CallInfo{
		CallID:      "AABBCCDDEEFF00112233445566778899",
		PeerJID:     peer,
		CallCreator: creator,
	}
	node := cli.BuildOfferStanza(info, []byte("cipher"), "msg", false)
	if _, exists := node.Attrs["from"]; exists {
		t.Fatalf("offer stanza should not include outer from attr")
	}
	if _, exists := node.Attrs["notify"]; exists {
		t.Fatalf("offer stanza should not include outer notify attr")
	}
	if _, exists := node.Attrs["e"]; exists {
		t.Fatalf("offer stanza should not include outer e attr")
	}
	if _, exists := node.Attrs["platform"]; exists {
		t.Fatalf("offer stanza should not include outer platform attr")
	}
	if _, exists := node.Attrs["version"]; exists {
		t.Fatalf("offer stanza should not include outer version attr")
	}

	children, ok := node.Content.([]waBinary.Node)
	if !ok || len(children) != 1 {
		t.Fatalf("expected single offer child")
	}
	offer := children[0]
	if got, _ := offer.Attrs["call-creator"].(types.JID); got != creator.ToNonAD() {
		t.Fatalf("unexpected call-creator attr: got %v want %v", got, creator.ToNonAD())
	}
	if _, hasCallerPN := offer.Attrs["caller_pn"]; hasCallerPN {
		t.Fatalf("caller_pn should not be auto-populated for outbound waweb-style offer")
	}
}

func TestParseRelayElectionBinaryShortPayload(t *testing.T) {
	from := types.NewJID("15550001", types.DefaultUserServer)
	creator := types.NewJID("15550002", types.DefaultUserServer)

	tests := []struct {
		name    string
		content []byte
		want    uint32
	}{
		{name: "single byte", content: []byte{0x7f}, want: 0x7f},
		{name: "two bytes", content: []byte{0x01, 0x02}, want: 0x0102},
		{name: "three bytes", content: []byte{0x0a, 0x0b, 0x0c}, want: 0x0a0b0c},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			node := &waBinary.Node{
				Tag: "call",
				Attrs: waBinary.Attrs{
					"id":   "stanza-relay-election-" + tc.name,
					"from": from,
					"t":    "1",
				},
				Content: []waBinary.Node{{
					Tag: "relay_election",
					Attrs: waBinary.Attrs{
						"call-id":      "call-relay-election-1",
						"call-creator": creator,
					},
					Content: tc.content,
				}},
			}

			parsed, err := ParseCallStanza(node)
			if err != nil {
				t.Fatalf("ParseCallStanza returned error: %v", err)
			}
			if parsed.RelayElection == nil {
				t.Fatalf("expected relay election payload")
			}
			if parsed.RelayElection.ElectedRelayIndex != tc.want {
				t.Fatalf("unexpected relay index: got %d want %d", parsed.RelayElection.ElectedRelayIndex, tc.want)
			}
		})
	}
}

func TestBuildCallAckAndReceiptDirectionality(t *testing.T) {
	peer := types.NewJID("15550002", types.DefaultUserServer)
	self := types.NewJID("15550001", types.DefaultUserServer)
	callCreator := types.NewJID("15550003", types.DefaultUserServer)

	ack := BuildCallAck("stanza-ack-1", peer, types.SignalingTransport, "call-ack-1", callCreator)
	if got, _ := ack.Attrs["to"].(types.JID); got != peer {
		t.Fatalf("unexpected ack to attr: got %v want %v", got, peer)
	}
	if got, _ := ack.Attrs["id"].(string); got != "stanza-ack-1" {
		t.Fatalf("unexpected ack id attr: got %q want %q", got, "stanza-ack-1")
	}

	receipt := BuildCallReceipt("stanza-receipt-1", peer, self, types.SignalingOffer, "call-receipt-1", callCreator)
	if got, _ := receipt.Attrs["to"].(types.JID); got != peer {
		t.Fatalf("unexpected receipt to attr: got %v want %v", got, peer)
	}
	if got, _ := receipt.Attrs["from"].(types.JID); got != self {
		t.Fatalf("unexpected receipt from attr: got %v want %v", got, self)
	}
}

func TestBuildEncRekeyStanza(t *testing.T) {
	own := types.NewJID("15550001", types.DefaultUserServer)
	peer := types.NewJID("15550002", types.DefaultUserServer)
	cli := &Client{Store: &store.Device{ID: &own}}

	info := &types.CallInfo{
		CallID:      "call-rekey-1",
		PeerJID:     peer,
		CallCreator: own,
	}
	cipher := []byte{0xde, 0xad, 0xbe, 0xef}
	node := cli.BuildEncRekeyStanza(info, cipher, "msg", 3)

	children, ok := node.Content.([]waBinary.Node)
	if !ok || len(children) != 1 {
		t.Fatalf("expected single enc_rekey child")
	}
	encRekey := children[0]
	if encRekey.Tag != "enc_rekey" {
		t.Fatalf("unexpected child tag: %s", encRekey.Tag)
	}
	if got, _ := encRekey.Attrs["call-id"].(string); got != info.CallID {
		t.Fatalf("unexpected call-id: got %q want %q", got, info.CallID)
	}
	if got, _ := encRekey.Attrs["call-creator"].(types.JID); got != own.ToNonAD() {
		t.Fatalf("unexpected call-creator: got %v want %v", got, own.ToNonAD())
	}

	encChildren, ok := encRekey.Content.([]waBinary.Node)
	if !ok || len(encChildren) != 1 {
		t.Fatalf("expected single enc child")
	}
	enc := encChildren[0]
	if enc.Tag != "enc" {
		t.Fatalf("unexpected inner tag: %s", enc.Tag)
	}
	if got, _ := enc.Attrs["type"].(string); got != "msg" {
		t.Fatalf("unexpected enc type: %q", got)
	}
	if got, _ := enc.Attrs["count"].(string); got != "3" {
		t.Fatalf("unexpected enc count: %q", got)
	}
	if got, ok := enc.Content.([]byte); !ok || !bytes.Equal(got, cipher) {
		t.Fatalf("unexpected enc ciphertext content")
	}
}

func TestDecodeBase64OrRawBytesBehavior(t *testing.T) {
	decodedFromString, ok := decodeBase64OrRawBytes("dG9rZW4=")
	if !ok {
		t.Fatalf("expected string content to decode")
	}
	if !bytes.Equal(decodedFromString, []byte("token")) {
		t.Fatalf("unexpected decoded string content: %q", decodedFromString)
	}

	rawBytes := []byte("dG9rZW4=")
	decodedFromBytes, ok := decodeBase64OrRawBytes(rawBytes)
	if !ok {
		t.Fatalf("expected []byte content to decode as raw")
	}
	if !bytes.Equal(decodedFromBytes, rawBytes) {
		t.Fatalf("expected []byte payload to be preserved as raw data")
	}
}

func TestBuildVoIPUSyncDevicesNodeIncludesVoIPContextAndHint(t *testing.T) {
	peer := types.NewJID("109822716420216", types.HiddenUserServer)
	node := buildVoIPUSyncDevicesNode("sid-1", peer, "2:zkJmKiqw", 1770987089)
	if node.Tag != "usync" {
		t.Fatalf("unexpected tag: %s", node.Tag)
	}
	if got, _ := node.Attrs["context"].(string); got != "voip" {
		t.Fatalf("unexpected context: %q", got)
	}
	if got, _ := node.Attrs["mode"].(string); got != "query" {
		t.Fatalf("unexpected mode: %q", got)
	}

	children, ok := node.Content.([]waBinary.Node)
	if !ok || len(children) != 2 {
		t.Fatalf("expected query/list children, got %#v", node.Content)
	}
	list := children[1]
	users, ok := list.Content.([]waBinary.Node)
	if !ok || len(users) != 1 {
		t.Fatalf("expected one user in usync list")
	}
	user := users[0]
	if got, _ := user.Attrs["jid"].(types.JID); got != peer.ToNonAD() {
		t.Fatalf("unexpected user jid: got %s want %s", got, peer.ToNonAD())
	}
	deviceNodes, ok := user.Content.([]waBinary.Node)
	if !ok || len(deviceNodes) != 1 || deviceNodes[0].Tag != "devices" {
		t.Fatalf("expected devices hint node in user")
	}
	if got, _ := deviceNodes[0].Attrs["device_hash"].(string); got != "2:zkJmKiqw" {
		t.Fatalf("unexpected device_hash hint: %q", got)
	}
	if got, _ := deviceNodes[0].Attrs["ts"].(string); got != "1770987089" {
		t.Fatalf("unexpected ts hint: %q", got)
	}
}

func TestGetCachedVoIPDeviceSyncHintUsesUserDeviceCache(t *testing.T) {
	peer := types.NewJID("109822716420216", types.HiddenUserServer)
	cli := &Client{
		userDevicesCache: map[types.JID]deviceCache{
			peer.ToNonAD(): {
				dhash: "2:zkJmKiqw",
				ts:    time.Now().Unix(),
			},
		},
	}
	hash, ts := cli.getCachedVoIPDeviceSyncHint(peer)
	if hash != "2:zkJmKiqw" {
		t.Fatalf("unexpected hash: %q", hash)
	}
	if ts <= 0 {
		t.Fatalf("expected positive ts, got %d", ts)
	}
}

func TestResolveCallKeySenderJIDPrefersLIDMapping(t *testing.T) {
	own := types.NewJID("15550001", types.DefaultUserServer)
	lidMapped := types.NewJID("99887766", types.HiddenUserServer)
	testStore := &testCallLIDSessionStore{
		lidByPN: map[string]types.JID{
			"15550002": lidMapped,
		},
	}
	cli := &Client{
		Store: &store.Device{
			ID:       &own,
			Sessions: testStore,
			LIDs:     testStore,
		},
	}
	parsed := &ParsedCallStanza{
		CallerPN:    types.NewJID("15550002", types.DefaultUserServer),
		CallCreator: types.NewJID("15550002", types.DefaultUserServer),
		From:        types.NewJID("15550002", types.DefaultUserServer),
	}

	got := cli.resolveCallKeySenderJID(context.Background(), parsed)
	want := types.NewJID("99887766", types.HiddenUserServer)
	if got != want {
		t.Fatalf("unexpected sender JID: got %s want %s", got, want)
	}
	if len(testStore.migrations) != 1 {
		t.Fatalf("expected one migration call, got %d", len(testStore.migrations))
	}
	if !reflect.DeepEqual(testStore.migrations[0], [2]types.JID{parsed.CallerPN.ToNonAD(), want}) {
		t.Fatalf("unexpected migration pair: got %+v", testStore.migrations[0])
	}
}

func TestResolveCallKeySenderJIDUsesCallCreatorLIDWhenPresent(t *testing.T) {
	own := types.NewJID("15550001", types.DefaultUserServer)
	callerPN := types.NewJID("15550002", types.DefaultUserServer)
	callCreatorLID := types.NewJID("99887766", types.HiddenUserServer)
	testStore := &testCallLIDSessionStore{}
	cli := &Client{
		Store: &store.Device{
			ID:       &own,
			Sessions: testStore,
			LIDs:     testStore,
		},
	}
	parsed := &ParsedCallStanza{
		CallerPN:    callerPN,
		CallCreator: callCreatorLID,
		From:        callerPN,
	}

	got := cli.resolveCallKeySenderJID(context.Background(), parsed)
	if got != callCreatorLID {
		t.Fatalf("unexpected sender JID: got %s want %s", got, callCreatorLID)
	}
	if len(testStore.migrations) != 1 {
		t.Fatalf("expected one migration call, got %d", len(testStore.migrations))
	}
	if !reflect.DeepEqual(testStore.migrations[0], [2]types.JID{callerPN, callCreatorLID}) {
		t.Fatalf("unexpected migration pair: got %+v", testStore.migrations[0])
	}
}

func TestResolveCallKeySenderJIDFallsBackToPN(t *testing.T) {
	own := types.NewJID("15550001", types.DefaultUserServer)
	callerPN := types.NewJID("15550002", types.DefaultUserServer)
	testStore := &testCallLIDSessionStore{}
	cli := &Client{
		Store: &store.Device{
			ID:       &own,
			Sessions: testStore,
			LIDs:     testStore,
		},
	}
	parsed := &ParsedCallStanza{
		CallerPN:    callerPN,
		CallCreator: callerPN,
		From:        callerPN,
	}

	got := cli.resolveCallKeySenderJID(context.Background(), parsed)
	if got != callerPN {
		t.Fatalf("unexpected sender JID fallback: got %s want %s", got, callerPN)
	}
	if len(testStore.migrations) != 0 {
		t.Fatalf("expected no migration when no LID mapping exists, got %d", len(testStore.migrations))
	}
}

func TestParseCallStanzaOfferExtensionsAndRelayParticipants(t *testing.T) {
	from := types.NewJID("102765716062358", types.HiddenUserServer)
	creator := types.NewJID("102765716062358", types.HiddenUserServer)
	participant := types.NewJID("102765716062358", types.HiddenUserServer)
	peer := types.NewJID("554396160286", types.DefaultUserServer)

	node := &waBinary.Node{
		Tag: "call",
		Attrs: waBinary.Attrs{
			"id":       "stanza-offer-extensions",
			"from":     from,
			"t":        "1771729219",
			"notify":   "Gustavo Quadri",
			"platform": "iphone",
			"version":  "2.26.5.77",
			"e":        "0",
		},
		Content: []waBinary.Node{{
			Tag: "offer",
			Attrs: waBinary.Attrs{
				"call-id":             "20D6EA8FBB4CD7D5EE85749DD60CDB8C",
				"call-creator":        creator,
				"caller_pn":           peer,
				"caller_country_code": "BR",
				"joinable":            "1",
			},
			Content: []waBinary.Node{
				{Tag: "audio", Attrs: waBinary.Attrs{"enc": "opus", "rate": "16000"}},
				{Tag: "audio", Attrs: waBinary.Attrs{"enc": "opus", "rate": "8000"}},
				{Tag: "capability", Attrs: waBinary.Attrs{"ver": "1"}, Content: "0105ff09e4fa13"},
				{Tag: "enc", Attrs: waBinary.Attrs{"type": "msg", "v": "2"}, Content: []byte{0x01, 0x02, 0x03}},
				{Tag: "encopt", Attrs: waBinary.Attrs{"keygen": "2"}},
				{Tag: "metadata", Attrs: waBinary.Attrs{"peer_abtest_bucket": "", "peer_abtest_bucket_id_list": "101891,102418,95019"}},
				{Tag: "net", Attrs: waBinary.Attrs{"medium": "3"}},
				{Tag: "rte", Content: "2da0ee43c6c3"},
				{Tag: "uploadfieldstat"},
				{Tag: "voip_settings", Attrs: waBinary.Attrs{"uncompressed": "1"}, Content: `{"options":{"disable_p2p":"1"}}`},
				{
					Tag:   "relay",
					Attrs: waBinary.Attrs{"uuid": "M3sunMduR9FMqucY", "self_pid": "3", "peer_pid": "1"},
					Content: []waBinary.Node{
						{Tag: "participant", Attrs: waBinary.Attrs{"jid": participant, "pid": "1"}},
						{Tag: "token", Attrs: waBinary.Attrs{"id": "0"}, Content: []byte{0xAA, 0xBB}},
						{Tag: "auth_token", Attrs: waBinary.Attrs{"id": "0"}, Content: "0903680b"},
						{Tag: "key", Content: base64.StdEncoding.EncodeToString([]byte{0x11, 0x22, 0x33, 0x44})},
						{Tag: "hbh_key", Content: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 30))},
						{Tag: "te2", Attrs: waBinary.Attrs{"auth_token_id": "0", "c2r_rtt": "16", "protocol": "1", "relay_id": "0", "relay_name": "gru1c01", "token_id": "0"}, Content: []byte{157, 240, 222, 62, 0x0D, 0x98}},
					},
				},
			},
		}},
	}

	parsed, err := ParseCallStanza(node)
	if err != nil {
		t.Fatalf("ParseCallStanza returned error: %v", err)
	}
	if !parsed.Joinable || parsed.CallerCountryCode != "BR" {
		t.Fatalf("unexpected offer attrs: joinable=%v caller_country_code=%q", parsed.Joinable, parsed.CallerCountryCode)
	}
	if !bytes.Equal(parsed.Capability, []byte{0x01, 0x05, 0xFF, 0x09, 0xE4, 0xFA, 0x13}) {
		t.Fatalf("unexpected capability bytes: %x", parsed.Capability)
	}
	if parsed.Metadata == nil || parsed.Metadata.PeerABTestBucketIDList != "101891,102418,95019" {
		t.Fatalf("unexpected metadata parsing: %+v", parsed.Metadata)
	}
	if !bytes.Equal(parsed.RTE, []byte{0x2d, 0xa0, 0xee, 0x43, 0xc6, 0xc3}) {
		t.Fatalf("unexpected rte bytes: %x", parsed.RTE)
	}
	if !parsed.HasUploadFieldStat {
		t.Fatalf("expected uploadfieldstat presence")
	}
	if parsed.VoIPSettings != `{"options":{"disable_p2p":"1"}}` {
		t.Fatalf("unexpected voip_settings: %q", parsed.VoIPSettings)
	}
	if parsed.OfferExtensions == nil || !parsed.OfferExtensions.UploadFieldStat {
		t.Fatalf("expected offer extensions to be populated")
	}
	if parsed.RelayData == nil || len(parsed.RelayData.Participants) != 1 {
		t.Fatalf("expected relay participants to be parsed")
	}
	if parsed.RelayData.Participants[0].JID != participant || parsed.RelayData.Participants[0].PID != 1 {
		t.Fatalf("unexpected relay participant: %+v", parsed.RelayData.Participants[0])
	}
	if len(parsed.RelayData.AuthTokens) != 1 || !bytes.Equal(parsed.RelayData.AuthTokens[0], []byte{0x09, 0x03, 0x68, 0x0b}) {
		t.Fatalf("unexpected auth token decode: %x", parsed.RelayData.AuthTokens[0])
	}
}

func TestBuildOfferStanzaUsesMinimalWAWebDefaults(t *testing.T) {
	own := types.NewJID("15550001", types.DefaultUserServer)
	peer := types.NewJID("15550002", types.DefaultUserServer)
	cli := &Client{Store: &store.Device{ID: &own}}

	info := &types.CallInfo{
		CallID:      "20D6EA8FBB4CD7D5EE85749DD60CDB8C",
		PeerJID:     peer,
		CallCreator: own,
	}
	node := cli.BuildOfferStanza(info, []byte{0x01, 0x02}, "msg", false)

	callChildren, ok := node.Content.([]waBinary.Node)
	if !ok || len(callChildren) != 1 {
		t.Fatalf("expected single offer child")
	}
	offer := callChildren[0]
	if _, hasJoinable := offer.Attrs["joinable"]; hasJoinable {
		t.Fatalf("joinable should not be auto-populated")
	}
	offerChildren, ok := offer.Content.([]waBinary.Node)
	if !ok {
		t.Fatalf("expected offer children")
	}
	hasMetadata := false
	hasRTE := false
	hasUploadFieldStat := false
	for _, child := range offerChildren {
		switch child.Tag {
		case "metadata":
			hasMetadata = true
		case "rte":
			hasRTE = true
		case "uploadfieldstat":
			hasUploadFieldStat = true
		}
	}
	if hasMetadata || hasRTE || hasUploadFieldStat {
		t.Fatalf("metadata/rte/uploadfieldstat should be opt-in only: metadata=%v rte=%v uploadfieldstat=%v", hasMetadata, hasRTE, hasUploadFieldStat)
	}
}

func TestBuildOfferStanzaUsesCustomExtensions(t *testing.T) {
	own := types.NewJID("15550001", types.DefaultUserServer)
	peer := types.NewJID("15550002", types.DefaultUserServer)
	cli := &Client{Store: &store.Device{ID: &own}}

	info := &types.CallInfo{
		CallID:      "20D6EA8FBB4CD7D5EE85749DD60CDB8C",
		PeerJID:     peer,
		CallCreator: own,
		OfferExtensions: &types.CallOfferExtensions{
			Joinable:          true,
			CallerCountryCode: "BR",
			Capability:        []byte{0x01, 0x05, 0xFF, 0x09, 0xE4, 0xFA, 0x13},
			Metadata: &types.CallOfferMetadata{
				PeerABTestBucket:       "A",
				PeerABTestBucketIDList: "101,102",
			},
			RTE:             []byte{0x2d, 0xa0, 0xee, 0x43, 0xc6, 0xc3},
			UploadFieldStat: true,
			VoIPSettings:    `{"options":{"disable_p2p":"1"}}`,
		},
	}
	node := cli.BuildOfferStanza(info, []byte{0x01, 0x02}, "msg", false)

	callChildren, ok := node.Content.([]waBinary.Node)
	if !ok || len(callChildren) != 1 {
		t.Fatalf("expected single offer child")
	}
	offer := callChildren[0]
	if got, _ := offer.Attrs["caller_country_code"].(string); got != "BR" {
		t.Fatalf("unexpected caller_country_code: %q", got)
	}

	offerChildren, ok := offer.Content.([]waBinary.Node)
	if !ok {
		t.Fatalf("expected offer children")
	}
	var capability, metadata, rte, voip *waBinary.Node
	for i := range offerChildren {
		switch offerChildren[i].Tag {
		case "capability":
			capability = &offerChildren[i]
		case "metadata":
			metadata = &offerChildren[i]
		case "rte":
			rte = &offerChildren[i]
		case "voip_settings":
			voip = &offerChildren[i]
		}
	}
	if capability == nil || metadata == nil || rte == nil || voip == nil {
		t.Fatalf("missing expected custom extension nodes")
	}
	if got, ok := capability.Content.([]byte); !ok || !bytes.Equal(got, info.OfferExtensions.Capability) {
		t.Fatalf("unexpected capability content")
	}
	if got, _ := metadata.Attrs["peer_abtest_bucket_id_list"].(string); got != "101,102" {
		t.Fatalf("unexpected metadata attrs: %v", metadata.Attrs)
	}
	if got, ok := rte.Content.([]byte); !ok || !bytes.Equal(got, info.OfferExtensions.RTE) {
		t.Fatalf("unexpected rte content")
	}
	if got, _ := voip.Attrs["uncompressed"].(string); got != "1" {
		t.Fatalf("unexpected voip_settings attrs: %v", voip.Attrs)
	}
	if got, ok := voip.Content.(string); !ok || got != info.OfferExtensions.VoIPSettings {
		t.Fatalf("unexpected voip_settings content: %#v", voip.Content)
	}
}

func TestBuildOfferStanzaWithDestinationsMatchesWAWebShape(t *testing.T) {
	own := types.NewJID("102765716062358", types.HiddenUserServer)
	peer := types.NewJID("109822716420216", types.HiddenUserServer)
	cli := &Client{Store: &store.Device{ID: &own}}

	info := &types.CallInfo{
		CallID:      "64FAF9E8E5E36F1B766A1BB0BA7D9122",
		PeerJID:     peer,
		CallCreator: own,
		OfferExtensions: &types.CallOfferExtensions{
			Privacy: []byte{0x04, 0x01, 0x22, 0x8E, 0xA0, 0x54, 0x58, 0xB1, 0x1D, 0xC0, 0x68},
		},
	}
	targets := []CallOfferEncryptedTarget{{
		JID:        peer,
		Ciphertext: []byte{0x01, 0x02, 0x03},
		EncType:    "pkmsg",
		Count:      0,
	}}

	node := cli.BuildOfferStanzaWithDestinations(info, targets, true)

	callChildren, ok := node.Content.([]waBinary.Node)
	if !ok || len(callChildren) != 1 {
		t.Fatalf("expected single offer child")
	}
	offer := callChildren[0]
	if len(offer.Attrs) != 2 {
		t.Fatalf("expected only call-id and call-creator attrs in default waweb offer, got %v", offer.Attrs)
	}
	if got, _ := offer.Attrs["call-id"].(string); got != info.CallID {
		t.Fatalf("unexpected call-id: %q", got)
	}
	if got, _ := offer.Attrs["call-creator"].(types.JID); got != info.CallCreator {
		t.Fatalf("unexpected call-creator: %v", got)
	}

	children, ok := offer.Content.([]waBinary.Node)
	if !ok {
		t.Fatalf("expected offer children")
	}
	gotTags := make([]string, 0, len(children))
	for _, child := range children {
		gotTags = append(gotTags, child.Tag)
	}
	wantTags := []string{"privacy", "audio", "audio", "net", "capability", "destination", "encopt", "device-identity"}
	if !reflect.DeepEqual(gotTags, wantTags) {
		t.Fatalf("unexpected offer child order: got %v want %v", gotTags, wantTags)
	}
	if got, _ := children[0].Content.(string); got != "0401228EA05458B11DC068" {
		t.Fatalf("unexpected privacy content: %q", got)
	}
	destination := children[5]
	destChildren, ok := destination.Content.([]waBinary.Node)
	if !ok || len(destChildren) != 1 {
		t.Fatalf("expected destination/to child")
	}
	toChildren, ok := destChildren[0].Content.([]waBinary.Node)
	if !ok || len(toChildren) != 1 {
		t.Fatalf("expected destination/to/enc child")
	}
	enc := toChildren[0]
	if got, _ := enc.Attrs["type"].(string); got != "pkmsg" {
		t.Fatalf("unexpected enc type: %q", got)
	}
	if got, _ := enc.Attrs["v"].(string); got != "2" {
		t.Fatalf("unexpected enc v: %q", got)
	}
	if got, _ := enc.Attrs["count"].(string); got != "0" {
		t.Fatalf("unexpected enc count: %q", got)
	}
}

func TestBuildOfferStanzaIncludesRelayDataWhenProvided(t *testing.T) {
	own := types.NewJID("15550001", types.DefaultUserServer)
	peer := types.NewJID("99887766", types.HiddenUserServer)
	cli := &Client{Store: &store.Device{ID: &own}}

	rtt := uint32(16)
	info := &types.CallInfo{
		CallID:      "20D6EA8FBB4CD7D5EE85749DD60CDB8C",
		PeerJID:     peer,
		CallCreator: types.NewJID("11223344", types.HiddenUserServer),
		OfferExtensions: &types.CallOfferExtensions{
			Joinable: true,
		},
		RelayData: &types.RelayData{
			AttributePadding: true,
			UUID:             "M3sunMduR9FMqucY",
			SelfPID:          3,
			PeerPID:          1,
			Participants: []types.RelayParticipant{{
				JID: types.NewJID("11223344", types.HiddenUserServer),
				PID: 1,
			}},
			RelayTokens: [][]byte{{0xAA, 0xBB}},
			AuthTokens:  [][]byte{{0xCC, 0xDD}},
			RelayKey:    []byte{0x01, 0x02, 0x03, 0x04},
			HBHKey:      bytes.Repeat([]byte{0x11}, 30),
			Endpoints: []types.RelayEndpoint{{
				RelayID:     0,
				RelayName:   "gru1c01",
				TokenID:     0,
				AuthTokenID: 0,
				C2RRTTMs:    &rtt,
				Addresses: []types.RelayAddress{{
					IPv4:     "157.240.222.62",
					Port:     3480,
					Protocol: 1,
				}},
			}},
		},
	}
	node := cli.BuildOfferStanza(info, []byte{0x01, 0x02}, "msg", false)

	callChildren, ok := node.Content.([]waBinary.Node)
	if !ok || len(callChildren) != 1 {
		t.Fatalf("expected single offer child")
	}
	offer := callChildren[0]
	offerChildren, ok := offer.Content.([]waBinary.Node)
	if !ok {
		t.Fatalf("expected offer children")
	}
	var relay *waBinary.Node
	for i := range offerChildren {
		if offerChildren[i].Tag == "relay" {
			relay = &offerChildren[i]
			break
		}
	}
	if relay == nil {
		t.Fatalf("expected relay node to be present")
	}
	if got, _ := relay.Attrs["attribute_padding"].(string); got != "1" {
		t.Fatalf("unexpected relay attribute_padding: %q", got)
	}
	if got, _ := relay.Attrs["self_pid"].(string); got != "3" {
		t.Fatalf("unexpected relay self_pid: %q", got)
	}
	if got, _ := relay.Attrs["peer_pid"].(string); got != "1" {
		t.Fatalf("unexpected relay peer_pid: %q", got)
	}

	relayChildren, ok := relay.Content.([]waBinary.Node)
	if !ok {
		t.Fatalf("expected relay children")
	}
	hasParticipant := false
	hasToken := false
	hasAuthToken := false
	hasKey := false
	hasHBH := false
	hasTE2 := false
	for _, child := range relayChildren {
		switch child.Tag {
		case "participant":
			hasParticipant = true
		case "token":
			hasToken = true
		case "auth_token":
			hasAuthToken = true
			if got, ok := child.Content.(string); !ok || got != "ccdd" {
				t.Fatalf("unexpected auth_token content: %#v", child.Content)
			}
		case "key":
			hasKey = true
		case "hbh_key":
			hasHBH = true
		case "te2":
			hasTE2 = true
			if got, _ := child.Attrs["protocol"].(string); got != "1" {
				t.Fatalf("unexpected te2 protocol: %q", got)
			}
		}
	}
	if !hasParticipant || !hasToken || !hasAuthToken || !hasKey || !hasHBH || !hasTE2 {
		t.Fatalf("missing relay children: participant=%v token=%v auth=%v key=%v hbh=%v te2=%v",
			hasParticipant, hasToken, hasAuthToken, hasKey, hasHBH, hasTE2)
	}
}
