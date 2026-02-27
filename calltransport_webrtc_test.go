// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mau.fi/whatsmeow/types"
)

type testWebRTCRelaySession struct {
	sent     [][]byte
	incoming func([]byte)
	closed   bool
}

func (s *testWebRTCRelaySession) Send(_ context.Context, payload []byte) error {
	copied := make([]byte, len(payload))
	copy(copied, payload)
	s.sent = append(s.sent, copied)
	return nil
}

func (s *testWebRTCRelaySession) Close(context.Context) error {
	s.closed = true
	return nil
}

func (s *testWebRTCRelaySession) SetIncomingHandler(handler func([]byte)) {
	s.incoming = handler
}

func TestWebRTCRelayCallTransportConnectSendClose(t *testing.T) {
	fast := uint32(10)
	slow := uint32(100)

	relayData := &types.RelayData{
		RelayKey:    []byte("relay-key"),
		RelayTokens: [][]byte{[]byte("relay-token")},
		AuthTokens:  [][]byte{[]byte("auth-token")},
		Endpoints: []types.RelayEndpoint{
			{RelayName: "slow", RelayID: 1, TokenID: 0, AuthTokenID: 0, C2RRTTMs: &slow, Addresses: []types.RelayAddress{{Protocol: 0, IPv4: "10.0.0.1", Port: 3480}}},
			{RelayName: "fast", RelayID: 2, TokenID: 0, AuthTokenID: 0, C2RRTTMs: &fast, Addresses: []types.RelayAddress{{Protocol: 0, IPv4: "10.0.0.2", Port: 3480}}},
		},
	}

	var mu sync.Mutex
	attempted := make(map[string]bool)
	sessions := make(map[string]*testWebRTCRelaySession)
	factory := WebRTCRelaySessionFactoryFunc(func(_ context.Context, _ *types.CallInfo, relay WebRTCRelayConnectionInfo) (WebRTCRelaySession, error) {
		mu.Lock()
		attempted[relay.RelayName] = true
		mu.Unlock()
		if relay.RelayName == "fast" {
			return nil, errors.New("simulated connection failure")
		}
		s := &testWebRTCRelaySession{}
		mu.Lock()
		sessions[relay.RelayName] = s
		mu.Unlock()
		return s, nil
	})

	transport := NewWebRTCRelayCallTransport(WebRTCRelayCallTransportConfig{SessionFactory: factory})
	callID := "call-webrtc-1"
	incoming := make(chan []byte, 1)
	transport.SetIncomingHandler(func(gotCallID string, payload []byte) {
		if gotCallID != callID {
			return
		}
		incoming <- payload
	})

	info := &types.CallInfo{CallID: callID, RelayData: relayData}
	if err := transport.Connect(context.Background(), info); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	mu.Lock()
	if !attempted["slow"] {
		t.Fatalf("expected successful relay to be attempted, got %v", attempted)
	}
	mu.Unlock()
	if transport.State(callID) != WebRTCTransportStateConnected {
		t.Fatalf("unexpected state after connect: %v", transport.State(callID))
	}
	if relay, ok := transport.ConnectedRelay(callID); !ok || relay.RelayName != "slow" {
		t.Fatalf("unexpected connected relay: %+v ok=%v", relay, ok)
	}

	payload := []byte("hello-webrtc")
	if err := transport.Send(context.Background(), info, payload); err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	mu.Lock()
	s := sessions["slow"]
	mu.Unlock()
	if s == nil || len(s.sent) != 1 || !bytes.Equal(s.sent[0], payload) {
		t.Fatalf("unexpected sent payloads: %+v", s)
	}

	if s.incoming == nil {
		t.Fatalf("expected incoming handler to be registered on session")
	}
	s.incoming([]byte("incoming-payload"))
	got := <-incoming
	if !bytes.Equal(got, []byte("incoming-payload")) {
		t.Fatalf("unexpected incoming payload: %q", got)
	}

	if err := transport.Close(context.Background(), info); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if !s.closed {
		t.Fatalf("expected session to be closed")
	}
	if transport.State(callID) != WebRTCTransportStateClosed {
		t.Fatalf("unexpected state after close: %v", transport.State(callID))
	}
	if err := transport.Send(context.Background(), info, []byte("after-close")); err == nil {
		t.Fatalf("expected send after close to fail")
	}
}

func TestGroupWebRTCRelaysByPriority(t *testing.T) {
	rtt10 := uint32(10)
	rtt20 := uint32(20)
	rtt30 := uint32(30)
	relays := []WebRTCRelayConnectionInfo{
		{RelayID: 1, RelayName: "r1a", C2RRTTMs: &rtt10},
		{RelayID: 1, RelayName: "r1b", C2RRTTMs: &rtt10},
		{RelayID: 2, RelayName: "r2", C2RRTTMs: &rtt20},
		{RelayID: 3, RelayName: "r3", C2RRTTMs: &rtt30},
	}

	grouped := groupWebRTCRelaysByPriority(relays)
	if len(grouped) != 3 {
		t.Fatalf("unexpected group count: got %d want 3", len(grouped))
	}
	if len(grouped[0]) != 2 || grouped[0][0].RelayID != 1 || grouped[0][1].RelayID != 1 {
		t.Fatalf("unexpected first relay group: %+v", grouped[0])
	}
	if len(grouped[1]) != 1 || grouped[1][0].RelayID != 2 {
		t.Fatalf("unexpected second relay group: %+v", grouped[1])
	}
	if len(grouped[2]) != 1 || grouped[2][0].RelayID != 3 {
		t.Fatalf("unexpected third relay group: %+v", grouped[2])
	}
}

func TestWebRTCRelayCallTransportConnectAttemptsRelayAddressesInParallel(t *testing.T) {
	rtt := uint32(10)
	relayData := &types.RelayData{
		RelayKey:    []byte("relay-key"),
		RelayTokens: [][]byte{[]byte("relay-token")},
		AuthTokens:  [][]byte{[]byte("auth-token")},
		Endpoints: []types.RelayEndpoint{
			{RelayName: "same-relay-a", RelayID: 7, TokenID: 0, AuthTokenID: 0, C2RRTTMs: &rtt, Addresses: []types.RelayAddress{{Protocol: 0, IPv4: "10.0.0.1", Port: 3480}}},
			{RelayName: "same-relay-b", RelayID: 7, TokenID: 0, AuthTokenID: 0, C2RRTTMs: &rtt, Addresses: []types.RelayAddress{{Protocol: 0, IPv4: "10.0.0.2", Port: 3480}}},
		},
	}

	var (
		mu          sync.Mutex
		attempted   = make(map[string]bool)
		inFlight    int
		maxInFlight int
	)

	factory := WebRTCRelaySessionFactoryFunc(func(_ context.Context, _ *types.CallInfo, relay WebRTCRelayConnectionInfo) (WebRTCRelaySession, error) {
		mu.Lock()
		attempted[relay.IP] = true
		inFlight++
		if inFlight > maxInFlight {
			maxInFlight = inFlight
		}
		mu.Unlock()

		time.Sleep(30 * time.Millisecond)

		mu.Lock()
		inFlight--
		mu.Unlock()

		if relay.IP == "10.0.0.2" {
			return &testWebRTCRelaySession{}, nil
		}
		return nil, errors.New("address failed")
	})

	transport := NewWebRTCRelayCallTransport(WebRTCRelayCallTransportConfig{
		SessionFactory: factory,
		ConnectTimeout: 500 * time.Millisecond,
	})
	info := &types.CallInfo{CallID: "call-webrtc-parallel", RelayData: relayData}
	if err := transport.Connect(context.Background(), info); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !attempted["10.0.0.1"] || !attempted["10.0.0.2"] {
		t.Fatalf("expected both relay addresses to be attempted, got %#v", attempted)
	}
	if maxInFlight < 2 {
		t.Fatalf("expected parallel attempts for same relay, max in-flight=%d", maxInFlight)
	}
}

func TestWebRTCRelayCallTransportConnectSucceedsWhenFirstGroupFails(t *testing.T) {
	best := uint32(10)
	next := uint32(20)
	relayData := &types.RelayData{
		RelayKey:    []byte("relay-key"),
		RelayTokens: [][]byte{[]byte("relay-token")},
		AuthTokens:  [][]byte{[]byte("auth-token")},
		Endpoints: []types.RelayEndpoint{
			{RelayName: "best-a", RelayID: 1, TokenID: 0, AuthTokenID: 0, C2RRTTMs: &best, Addresses: []types.RelayAddress{{Protocol: 0, IPv4: "10.0.1.1", Port: 3480}}},
			{RelayName: "best-b", RelayID: 1, TokenID: 0, AuthTokenID: 0, C2RRTTMs: &best, Addresses: []types.RelayAddress{{Protocol: 0, IPv4: "10.0.1.2", Port: 3480}}},
			{RelayName: "next", RelayID: 2, TokenID: 0, AuthTokenID: 0, C2RRTTMs: &next, Addresses: []types.RelayAddress{{Protocol: 0, IPv4: "10.0.2.1", Port: 3480}}},
		},
	}

	// All relay groups are attempted in parallel. The second group succeeds
	// even though the first group's addresses all fail.
	var secondGroupAttempted int32
	factory := WebRTCRelaySessionFactoryFunc(func(_ context.Context, _ *types.CallInfo, relay WebRTCRelayConnectionInfo) (WebRTCRelaySession, error) {
		switch relay.RelayID {
		case 1:
			time.Sleep(20 * time.Millisecond)
			return nil, errors.New("best relay address failed")
		case 2:
			atomic.StoreInt32(&secondGroupAttempted, 1)
			return &testWebRTCRelaySession{}, nil
		default:
			return nil, errors.New("unexpected relay id")
		}
	})

	transport := NewWebRTCRelayCallTransport(WebRTCRelayCallTransportConfig{
		SessionFactory: factory,
		ConnectTimeout: 500 * time.Millisecond,
	})
	info := &types.CallInfo{CallID: "call-webrtc-fallback", RelayData: relayData}
	if err := transport.Connect(context.Background(), info); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	connected, ok := transport.ConnectedRelay(info.CallID)
	if !ok {
		t.Fatalf("expected connected relay")
	}
	if connected.RelayID != 2 {
		t.Fatalf("unexpected connected relay id: got %d want 2", connected.RelayID)
	}
	if atomic.LoadInt32(&secondGroupAttempted) == 0 {
		t.Fatalf("expected second relay group to be attempted")
	}
}

func TestWebRTCRelayCallTransportRemoteAcceptAttemptsRelayGroupsInParallel(t *testing.T) {
	best := uint32(10)
	next := uint32(20)
	relayData := &types.RelayData{
		RelayKey:    []byte("relay-key"),
		RelayTokens: [][]byte{[]byte("relay-token")},
		AuthTokens:  [][]byte{[]byte("auth-token")},
		Endpoints: []types.RelayEndpoint{
			{RelayName: "best-a", RelayID: 1, TokenID: 0, AuthTokenID: 0, C2RRTTMs: &best, Addresses: []types.RelayAddress{{Protocol: 0, IPv4: "10.0.1.1", Port: 3480}}},
			{RelayName: "best-b", RelayID: 1, TokenID: 0, AuthTokenID: 0, C2RRTTMs: &best, Addresses: []types.RelayAddress{{Protocol: 0, IPv4: "10.0.1.2", Port: 3480}}},
			{RelayName: "next", RelayID: 2, TokenID: 0, AuthTokenID: 0, C2RRTTMs: &next, Addresses: []types.RelayAddress{{Protocol: 0, IPv4: "10.0.2.1", Port: 3480}}},
		},
	}

	var (
		firstGroupFinished int32
		earlySecondGroup   int32
	)
	factory := WebRTCRelaySessionFactoryFunc(func(_ context.Context, _ *types.CallInfo, relay WebRTCRelayConnectionInfo) (WebRTCRelaySession, error) {
		switch relay.RelayID {
		case 1:
			time.Sleep(40 * time.Millisecond)
			atomic.AddInt32(&firstGroupFinished, 1)
			return nil, errors.New("best relay address failed")
		case 2:
			if atomic.LoadInt32(&firstGroupFinished) == 0 {
				atomic.StoreInt32(&earlySecondGroup, 1)
			}
			return &testWebRTCRelaySession{}, nil
		default:
			return nil, errors.New("unexpected relay id")
		}
	})

	transport := NewWebRTCRelayCallTransport(WebRTCRelayCallTransportConfig{
		SessionFactory: factory,
		ConnectTimeout: 2 * time.Second,
	})
	info := &types.CallInfo{CallID: "call-webrtc-remote-accept-parallel", RelayData: relayData}
	ctx := withCallTransportAttemptTrace(context.Background(), "attempt-1", "remote_accept")
	if err := transport.Connect(ctx, info); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	connected, ok := transport.ConnectedRelay(info.CallID)
	if !ok {
		t.Fatalf("expected connected relay")
	}
	if connected.RelayID != 2 {
		t.Fatalf("unexpected connected relay id: got %d want 2", connected.RelayID)
	}
	if atomic.LoadInt32(&earlySecondGroup) == 0 {
		t.Fatalf("expected second relay group to start before first group fully failed in remote_accept mode")
	}
}

func TestWebRTCRelayCallTransportStateHandlerReceivesFailureReason(t *testing.T) {
	rtt := uint32(10)
	relayData := &types.RelayData{
		RelayKey:    []byte("relay-key"),
		RelayTokens: [][]byte{[]byte("relay-token")},
		AuthTokens:  [][]byte{[]byte("auth-token")},
		Endpoints: []types.RelayEndpoint{
			{RelayName: "relay-fail", RelayID: 1, TokenID: 0, AuthTokenID: 0, C2RRTTMs: &rtt, Addresses: []types.RelayAddress{{Protocol: 0, IPv4: "10.0.0.1", Port: 3480}}},
		},
	}
	expectedErr := fmt.Errorf("simulated connect failure")
	factory := WebRTCRelaySessionFactoryFunc(func(_ context.Context, _ *types.CallInfo, _ WebRTCRelayConnectionInfo) (WebRTCRelaySession, error) {
		return nil, expectedErr
	})

	var (
		states  []WebRTCTransportState
		reasons []string
	)
	transport := NewWebRTCRelayCallTransport(WebRTCRelayCallTransportConfig{
		SessionFactory: factory,
		StateHandler: func(_ string, state WebRTCTransportState, reason error) {
			states = append(states, state)
			if reason != nil {
				reasons = append(reasons, reason.Error())
			} else {
				reasons = append(reasons, "")
			}
		},
	})
	info := &types.CallInfo{CallID: "call-webrtc-state", RelayData: relayData}
	err := transport.Connect(context.Background(), info)
	if err == nil {
		t.Fatalf("expected connect error")
	}
	if len(states) == 0 {
		t.Fatalf("expected state callbacks")
	}
	if states[len(states)-1] != WebRTCTransportStateFailed {
		t.Fatalf("expected final state failed, got %v", states[len(states)-1])
	}
	if len(reasons) == 0 || reasons[len(reasons)-1] == "" {
		t.Fatalf("expected failure reason in callback")
	}
}

func TestWebRTCRelayCallTransportStateHandlerReceivesConnected(t *testing.T) {
	rtt := uint32(10)
	relayData := &types.RelayData{
		RelayKey:    []byte("relay-key"),
		RelayTokens: [][]byte{[]byte("relay-token")},
		AuthTokens:  [][]byte{[]byte("auth-token")},
		Endpoints: []types.RelayEndpoint{
			{RelayName: "relay-ok", RelayID: 1, TokenID: 0, AuthTokenID: 0, C2RRTTMs: &rtt, Addresses: []types.RelayAddress{{Protocol: 0, IPv4: "10.0.0.1", Port: 3480}}},
		},
	}
	factory := WebRTCRelaySessionFactoryFunc(func(_ context.Context, _ *types.CallInfo, _ WebRTCRelayConnectionInfo) (WebRTCRelaySession, error) {
		return &testWebRTCRelaySession{}, nil
	})

	var states []WebRTCTransportState
	transport := NewWebRTCRelayCallTransport(WebRTCRelayCallTransportConfig{
		SessionFactory: factory,
		StateHandler: func(_ string, state WebRTCTransportState, _ error) {
			states = append(states, state)
		},
	})
	info := &types.CallInfo{CallID: "call-webrtc-state-connected", RelayData: relayData}
	if err := transport.Connect(context.Background(), info); err != nil {
		t.Fatalf("expected connect success, got error: %v", err)
	}
	if len(states) == 0 {
		t.Fatalf("expected state callbacks")
	}
	if states[len(states)-1] != WebRTCTransportStateConnected {
		t.Fatalf("expected final state connected, got %v", states[len(states)-1])
	}
}

func TestResolveRelayGroupConnectTimeout(t *testing.T) {
	t.Run("default timeout", func(t *testing.T) {
		got := resolveRelayGroupConnectTimeout(0, "offer_ack")
		if got != defaultWebRTCRelayConnectTimeout {
			t.Fatalf("unexpected default timeout: got %s want %s", got, defaultWebRTCRelayConnectTimeout)
		}
	})
	t.Run("remote accept capped", func(t *testing.T) {
		got := resolveRelayGroupConnectTimeout(20*time.Second, "remote_accept")
		if got != remoteAcceptRelayGroupConnectTimeout {
			t.Fatalf("unexpected remote_accept timeout: got %s want %s", got, remoteAcceptRelayGroupConnectTimeout)
		}
	})
	t.Run("remote accept keeps lower explicit timeout", func(t *testing.T) {
		want := 4 * time.Second
		got := resolveRelayGroupConnectTimeout(want, "remote_accept")
		if got != want {
			t.Fatalf("unexpected remote_accept timeout for lower explicit timeout: got %s want %s", got, want)
		}
	})
}

func TestWebRTCRelayCallTransportRemoteAcceptCredentialVariantsDisabledByDefault(t *testing.T) {
	rtt := uint32(10)
	relayData := &types.RelayData{
		RelayKey:    []byte("relay-key"),
		RelayTokens: [][]byte{[]byte("relay-token")},
		AuthTokens:  [][]byte{[]byte("auth-token")},
		Endpoints: []types.RelayEndpoint{
			{RelayName: "relay-a", RelayID: 1, TokenID: 0, AuthTokenID: 0, C2RRTTMs: &rtt, Addresses: []types.RelayAddress{{Protocol: 0, IPv4: "10.0.0.1", Port: 3480}}},
		},
	}

	var attempts int32
	factory := WebRTCRelaySessionFactoryFunc(func(_ context.Context, _ *types.CallInfo, _ WebRTCRelayConnectionInfo) (WebRTCRelaySession, error) {
		atomic.AddInt32(&attempts, 1)
		return nil, errors.New("forced connect failure")
	})

	transport := NewWebRTCRelayCallTransport(WebRTCRelayCallTransportConfig{
		SessionFactory: factory,
		ConnectTimeout: 100 * time.Millisecond,
	})
	info := &types.CallInfo{CallID: "call-webrtc-strict-cred", RelayData: relayData}
	err := transport.Connect(withCallTransportAttemptTrace(context.Background(), "attempt-cred-1", "remote_accept"), info)
	if err == nil {
		t.Fatalf("expected connect failure")
	}
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Fatalf("expected exactly one credential attempt in strict mode, got %d", got)
	}
}

func TestWebRTCRelayCallTransportRemoteAcceptCredentialVariantsEnabled(t *testing.T) {
	rtt := uint32(10)
	relayData := &types.RelayData{
		RelayKey:    []byte("relay-key"),
		RelayTokens: [][]byte{[]byte("relay-token")},
		AuthTokens:  [][]byte{[]byte("auth-token")},
		Endpoints: []types.RelayEndpoint{
			{RelayName: "relay-a", RelayID: 1, TokenID: 0, AuthTokenID: 0, C2RRTTMs: &rtt, Addresses: []types.RelayAddress{{Protocol: 0, IPv4: "10.0.0.1", Port: 3480}}},
		},
	}

	var attempts int32
	factory := WebRTCRelaySessionFactoryFunc(func(_ context.Context, _ *types.CallInfo, _ WebRTCRelayConnectionInfo) (WebRTCRelaySession, error) {
		atomic.AddInt32(&attempts, 1)
		return nil, errors.New("forced connect failure")
	})

	transport := NewWebRTCRelayCallTransport(WebRTCRelayCallTransportConfig{
		SessionFactory:                  factory,
		ConnectTimeout:                  100 * time.Millisecond,
		EnableCredentialVariantFallback: true,
	})
	info := &types.CallInfo{CallID: "call-webrtc-fallback-cred", RelayData: relayData}
	err := transport.Connect(withCallTransportAttemptTrace(context.Background(), "attempt-cred-2", "remote_accept"), info)
	if err == nil {
		t.Fatalf("expected connect failure")
	}
	if got := atomic.LoadInt32(&attempts); got <= 1 {
		t.Fatalf("expected multiple credential attempts when fallback is enabled, got %d", got)
	}
}
