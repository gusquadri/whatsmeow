// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.mau.fi/whatsmeow/types"
)

type testCallMediaEngine struct {
	startErr   error
	stopErr    error
	handleErr  error
	startCalls int
	stopCalls  int
	incoming   [][]byte
}

func (m *testCallMediaEngine) Start(context.Context, *types.CallInfo, *DerivedCallKeys) error {
	m.startCalls++
	return m.startErr
}

func (m *testCallMediaEngine) Stop(context.Context, *types.CallInfo) error {
	m.stopCalls++
	return m.stopErr
}

func (m *testCallMediaEngine) HandleIncomingPayload(_ context.Context, _ *types.CallInfo, payload []byte) error {
	if m.handleErr != nil {
		return m.handleErr
	}
	copied := make([]byte, len(payload))
	copy(copied, payload)
	m.incoming = append(m.incoming, copied)
	return nil
}

type testCallTransport struct {
	sendErr    error
	sent       [][]byte
	sendNotify chan struct{}
	incoming   IncomingCallTransportPayloadHandler
}

func (t *testCallTransport) Connect(context.Context, *types.CallInfo) error { return nil }
func (t *testCallTransport) Close(context.Context, *types.CallInfo) error   { return nil }
func (t *testCallTransport) Send(_ context.Context, _ *types.CallInfo, payload []byte) error {
	if t.sendErr != nil {
		return t.sendErr
	}
	copied := make([]byte, len(payload))
	copy(copied, payload)
	t.sent = append(t.sent, copied)
	if t.sendNotify != nil {
		select {
		case t.sendNotify <- struct{}{}:
		default:
		}
	}
	return nil
}
func (t *testCallTransport) SetIncomingHandler(handler IncomingCallTransportPayloadHandler) {
	t.incoming = handler
}

type stagedConnectTransport struct {
	firstRelease  chan struct{}
	secondRelease chan struct{}
	startNotify   chan int

	mu    sync.Mutex
	calls int
}

func (t *stagedConnectTransport) Connect(ctx context.Context, _ *types.CallInfo) error {
	t.mu.Lock()
	t.calls++
	callNum := t.calls
	t.mu.Unlock()
	if t.startNotify != nil {
		select {
		case t.startNotify <- callNum:
		default:
		}
	}

	switch callNum {
	case 1:
		select {
		case <-t.firstRelease:
		case <-ctx.Done():
			return ctx.Err()
		}
		return errors.New("first connect failed")
	case 2:
		select {
		case <-t.secondRelease:
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	default:
		return nil
	}
}

func (t *stagedConnectTransport) Close(context.Context, *types.CallInfo) error { return nil }
func (t *stagedConnectTransport) Send(context.Context, *types.CallInfo, []byte) error {
	return nil
}
func (t *stagedConnectTransport) SetIncomingHandler(IncomingCallTransportPayloadHandler) {}

type testPacketizingMediaEngine struct {
	startErr  error
	stopErr   error
	feedback  map[string][][]byte
	audioCh   chan []byte
	videoCh   chan []byte
	handledIn [][]byte
}

func (e *testPacketizingMediaEngine) Start(context.Context, *types.CallInfo, *DerivedCallKeys) error {
	return e.startErr
}
func (e *testPacketizingMediaEngine) Stop(context.Context, *types.CallInfo) error {
	return e.stopErr
}
func (e *testPacketizingMediaEngine) HandleIncomingPayload(_ context.Context, _ *types.CallInfo, payload []byte) error {
	copied := make([]byte, len(payload))
	copy(copied, payload)
	e.handledIn = append(e.handledIn, copied)
	return nil
}
func (e *testPacketizingMediaEngine) BuildOutgoingAudioPayload(callID string, frame []byte) ([]byte, error) {
	return append([]byte("rtp-a:"+callID+":"), frame...), nil
}
func (e *testPacketizingMediaEngine) BuildOutgoingVideoPayload(callID string, frame []byte) ([]byte, error) {
	return append([]byte("rtp-v:"+callID+":"), frame...), nil
}
func (e *testPacketizingMediaEngine) DrainOutgoingControl(callID string) [][]byte {
	if e.feedback == nil {
		return nil
	}
	out := e.feedback[callID]
	delete(e.feedback, callID)
	return out
}
func (e *testPacketizingMediaEngine) ReadOutgoingAudioFrame(ctx context.Context, _ string) ([]byte, error) {
	if e.audioCh == nil {
		return nil, ErrNoAudioSource
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case frame := <-e.audioCh:
		return frame, nil
	}
}
func (e *testPacketizingMediaEngine) ReadOutgoingVideoFrame(ctx context.Context, _ string) ([]byte, error) {
	if e.videoCh == nil {
		return nil, ErrNoVideoSource
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case frame := <-e.videoCh:
		return frame, nil
	}
}

func TestCallManagerStartMedia(t *testing.T) {
	tests := []struct {
		name             string
		state            types.CallState
		transportState   types.TransportState
		withKey          bool
		engineStartErr   error
		expectStarted    bool
		expectErr        bool
		expectMediaState types.MediaState
		expectStartCalls int
	}{
		{
			name:             "not connecting state",
			state:            types.CallStateRinging,
			transportState:   types.TransportStateConnected,
			withKey:          true,
			expectStarted:    false,
			expectErr:        false,
			expectMediaState: types.MediaStateNone,
			expectStartCalls: 0,
		},
		{
			name:             "transport not connected",
			state:            types.CallStateConnecting,
			transportState:   types.TransportStatePendingRelay,
			withKey:          true,
			expectStarted:    false,
			expectErr:        false,
			expectMediaState: types.MediaStateNone,
			expectStartCalls: 0,
		},
		{
			name:             "missing encryption key",
			state:            types.CallStateConnecting,
			transportState:   types.TransportStateConnected,
			withKey:          false,
			expectStarted:    false,
			expectErr:        true,
			expectMediaState: types.MediaStateFailed,
			expectStartCalls: 0,
		},
		{
			name:             "engine start failure",
			state:            types.CallStateConnecting,
			transportState:   types.TransportStateConnected,
			withKey:          true,
			engineStartErr:   errors.New("boom"),
			expectStarted:    false,
			expectErr:        true,
			expectMediaState: types.MediaStateFailed,
			expectStartCalls: 1,
		},
		{
			name:             "successful start",
			state:            types.CallStateConnecting,
			transportState:   types.TransportStateConnected,
			withKey:          true,
			expectStarted:    true,
			expectErr:        false,
			expectMediaState: types.MediaStateActive,
			expectStartCalls: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cli := &Client{}
			cm := NewCallManager(cli)
			callID := "call-start-media"
			cm.calls[callID] = &types.CallInfo{
				CallID:         callID,
				State:          tc.state,
				TransportState: tc.transportState,
			}
			if tc.withKey {
				cm.keys[callID] = &CallEncryptionKey{Generation: 1}
			}
			engine := &testCallMediaEngine{startErr: tc.engineStartErr}
			cm.SetMediaEngine(engine)

			started, err := cm.StartMedia(context.Background(), callID)
			if started != tc.expectStarted {
				t.Fatalf("unexpected started value: got %v want %v", started, tc.expectStarted)
			}
			if (err != nil) != tc.expectErr {
				t.Fatalf("unexpected error state: err=%v", err)
			}
			if engine.startCalls != tc.expectStartCalls {
				t.Fatalf("unexpected media engine start calls: got %d want %d", engine.startCalls, tc.expectStartCalls)
			}
			info := cm.GetCall(callID)
			if info == nil {
				t.Fatalf("expected call info to exist")
			}
			if info.MediaState != tc.expectMediaState {
				t.Fatalf("unexpected media state: got %v want %v", info.MediaState, tc.expectMediaState)
			}
			if tc.expectMediaState == types.MediaStateActive && info.MediaStartedAt.IsZero() {
				t.Fatalf("expected MediaStartedAt to be set")
			}
		})
	}
}

func TestCallManagerEnsureTransportPromotesConnectingCallToActive(t *testing.T) {
	cm := NewCallManager(&Client{})
	cm.SetTransport(&testCallTransport{})
	callID := "call-ensure-transport-active"
	cm.calls[callID] = &types.CallInfo{
		CallID: callID,
		State:  types.CallStateConnecting,
		RelayData: &types.RelayData{
			Endpoints: []types.RelayEndpoint{{
				RelayName: "relay-1",
				Addresses: []types.RelayAddress{{IPv4: "127.0.0.1", Port: defaultRelayPort}},
			}},
		},
		TransportState: types.TransportStatePendingRelay,
	}

	if err := cm.EnsureTransport(context.Background(), callID); err != nil {
		t.Fatalf("EnsureTransport failed: %v", err)
	}
	info := cm.GetCall(callID)
	if info == nil {
		t.Fatalf("expected call info after EnsureTransport")
	}
	if info.TransportState != types.TransportStateConnected {
		t.Fatalf("expected connected transport state, got %v", info.TransportState)
	}
	if info.State != types.CallStateActive {
		t.Fatalf("expected call state to transition to active, got %v", info.State)
	}
	if info.ConnectedAt.IsZero() {
		t.Fatalf("expected connected timestamp to be set")
	}
}

func TestCallManagerEnsureTransportSuppressesFailureWhileAnotherAttemptInFlight(t *testing.T) {
	cm := NewCallManager(&Client{})
	transport := &stagedConnectTransport{
		firstRelease:  make(chan struct{}),
		secondRelease: make(chan struct{}),
	}
	cm.SetTransport(transport)

	callID := "call-ensure-transport-concurrent-retry"
	cm.calls[callID] = &types.CallInfo{
		CallID: callID,
		State:  types.CallStateConnecting,
		RelayData: &types.RelayData{
			Endpoints: []types.RelayEndpoint{{
				RelayName: "relay-1",
				Addresses: []types.RelayAddress{{IPv4: "127.0.0.1", Port: defaultRelayPort}},
			}},
		},
		TransportState: types.TransportStatePendingRelay,
	}

	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	go func() { firstDone <- cm.EnsureTransport(context.Background(), callID) }()
	time.Sleep(20 * time.Millisecond)
	go func() { secondDone <- cm.EnsureTransport(context.Background(), callID) }()

	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("expected second EnsureTransport to coalesce without error, got: %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("timed out waiting for coalesced EnsureTransport call to return")
	}

	close(transport.firstRelease)

	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		transport.mu.Lock()
		started := transport.calls >= 2
		transport.mu.Unlock()
		if started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for second transport attempt to start")
		}
		time.Sleep(5 * time.Millisecond)
	}

	close(transport.secondRelease)
	if err := <-firstDone; err != nil {
		t.Fatalf("expected first EnsureTransport error to be retried and suppressed, got: %v", err)
	}

	info := cm.GetCall(callID)
	if info == nil {
		t.Fatalf("expected call info after EnsureTransport")
	}
	if info.TransportState != types.TransportStateConnected {
		t.Fatalf("expected connected transport state, got %v", info.TransportState)
	}
	if info.TransportConnectInFly != 0 {
		t.Fatalf("expected no in-flight transport attempts, got %d", info.TransportConnectInFly)
	}
}

func TestCallManagerEnsureTransportPreemptsStaleInFlightOnRemoteAccept(t *testing.T) {
	cm := NewCallManager(&Client{})
	transport := &stagedConnectTransport{
		firstRelease:  make(chan struct{}),
		secondRelease: make(chan struct{}),
		startNotify:   make(chan int, 4),
	}
	cm.SetTransport(transport)

	callID := "call-ensure-transport-preempt-remote-accept"
	cm.calls[callID] = &types.CallInfo{
		CallID: callID,
		State:  types.CallStateConnecting,
		RelayData: &types.RelayData{
			Endpoints: []types.RelayEndpoint{{
				RelayName: "relay-1",
				Addresses: []types.RelayAddress{{IPv4: "127.0.0.1", Port: defaultRelayPort}},
			}},
		},
		TransportState: types.TransportStatePendingRelay,
	}

	firstDone := make(chan error, 1)
	go func() { firstDone <- cm.EnsureTransport(context.Background(), callID) }()

	select {
	case started := <-transport.startNotify:
		if started != 1 {
			t.Fatalf("expected first transport attempt to start, got %d", started)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timed out waiting for first transport attempt to start")
	}

	cm.mu.Lock()
	info := cm.calls[callID]
	if info == nil {
		cm.mu.Unlock()
		t.Fatalf("expected call info to exist")
	}
	info.TransportLastAttemptAt = time.Now().Add(-(remoteAcceptPreemptAfter + time.Second))
	cm.mu.Unlock()

	if err := cm.EnsureTransport(withCallTransportAttemptTrace(context.Background(), "", "remote_accept"), callID); err != nil {
		t.Fatalf("expected remote_accept EnsureTransport to preempt without error, got: %v", err)
	}

	select {
	case started := <-transport.startNotify:
		if started != 2 {
			t.Fatalf("expected queued retry transport attempt to start as second attempt, got %d", started)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for queued retry attempt to start")
	}

	close(transport.secondRelease)

	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("expected first EnsureTransport to complete successfully after queued retry, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for first EnsureTransport to complete")
	}

	finalInfo := cm.GetCall(callID)
	if finalInfo == nil {
		t.Fatalf("expected final call info")
	}
	if finalInfo.TransportState != types.TransportStateConnected {
		t.Fatalf("expected connected transport state, got %v", finalInfo.TransportState)
	}
	if finalInfo.TransportConnectInFly != 0 {
		t.Fatalf("expected no in-flight transport attempts, got %d", finalInfo.TransportConnectInFly)
	}
}

func TestCallManagerEnsureTransportPreemptsInFlightOnRemoteAcceptSourceMismatch(t *testing.T) {
	cm := NewCallManager(&Client{})
	transport := &stagedConnectTransport{
		firstRelease:  make(chan struct{}),
		secondRelease: make(chan struct{}),
		startNotify:   make(chan int, 4),
	}
	cm.SetTransport(transport)

	callID := "call-ensure-transport-preempt-source-mismatch"
	cm.calls[callID] = &types.CallInfo{
		CallID: callID,
		State:  types.CallStateConnecting,
		RelayData: &types.RelayData{
			Endpoints: []types.RelayEndpoint{{
				RelayName: "relay-1",
				Addresses: []types.RelayAddress{{IPv4: "127.0.0.1", Port: defaultRelayPort}},
			}},
		},
		TransportState: types.TransportStatePendingRelay,
	}

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- cm.EnsureTransport(withCallTransportAttemptTrace(context.Background(), "", "offer_ack"), callID)
	}()

	select {
	case started := <-transport.startNotify:
		if started != 1 {
			t.Fatalf("expected first transport attempt to start, got %d", started)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timed out waiting for first transport attempt to start")
	}

	if err := cm.EnsureTransport(withCallTransportAttemptTrace(context.Background(), "", "remote_accept"), callID); err != nil {
		t.Fatalf("expected remote_accept EnsureTransport to preempt source-mismatched attempt without error, got: %v", err)
	}

	select {
	case started := <-transport.startNotify:
		if started != 2 {
			t.Fatalf("expected queued retry transport attempt to start as second attempt, got %d", started)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for queued retry attempt to start")
	}

	close(transport.secondRelease)

	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("expected first EnsureTransport to complete successfully after queued retry, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for first EnsureTransport to complete")
	}

	finalInfo := cm.GetCall(callID)
	if finalInfo == nil {
		t.Fatalf("expected final call info")
	}
	if finalInfo.TransportState != types.TransportStateConnected {
		t.Fatalf("expected connected transport state, got %v", finalInfo.TransportState)
	}
	if finalInfo.TransportConnectInFly != 0 {
		t.Fatalf("expected no in-flight transport attempts, got %d", finalInfo.TransportConnectInFly)
	}
}

func TestCallManagerEnsureTransportSuppressesErrorAfterTerminate(t *testing.T) {
	cm := NewCallManager(&Client{})
	transport := &stagedConnectTransport{
		firstRelease: make(chan struct{}),
		startNotify:  make(chan int, 2),
	}
	cm.SetTransport(transport)

	callID := "call-ensure-transport-suppress-after-terminate"
	cm.calls[callID] = &types.CallInfo{
		CallID: callID,
		State:  types.CallStateConnecting,
		RelayData: &types.RelayData{
			Endpoints: []types.RelayEndpoint{{
				RelayName: "relay-1",
				Addresses: []types.RelayAddress{{IPv4: "127.0.0.1", Port: defaultRelayPort}},
			}},
		},
		TransportState: types.TransportStatePendingRelay,
	}

	done := make(chan error, 1)
	go func() { done <- cm.EnsureTransport(context.Background(), callID) }()

	select {
	case started := <-transport.startNotify:
		if started != 1 {
			t.Fatalf("expected first transport attempt to start, got %d", started)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timed out waiting for transport attempt to start")
	}

	cm.HandleTerminate(&ParsedCallStanza{CallID: callID})
	if err := cm.CloseTransport(context.Background(), callID); err != nil {
		t.Fatalf("CloseTransport failed: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected EnsureTransport error to be suppressed after terminate, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for EnsureTransport completion")
	}
}

func TestCallManagerMediaPayloadStats(t *testing.T) {
	cli := &Client{}
	cm := NewCallManager(cli)
	callID := "call-media-stats"
	cm.calls[callID] = &types.CallInfo{
		CallID:         callID,
		State:          types.CallStateConnecting,
		TransportState: types.TransportStateConnected,
	}
	cm.keys[callID] = &CallEncryptionKey{Generation: 1}

	engine := &testCallMediaEngine{}
	transport := &testCallTransport{}
	cm.SetMediaEngine(engine)
	cm.SetTransport(transport)

	started, err := cm.StartMedia(context.Background(), callID)
	if err != nil {
		t.Fatalf("StartMedia failed: %v", err)
	}
	if !started {
		t.Fatalf("expected media to start")
	}

	outboundPayload := []byte{1, 2, 3, 4}
	if err := cm.SendMediaPayload(context.Background(), callID, outboundPayload); err != nil {
		t.Fatalf("SendMediaPayload failed: %v", err)
	}
	if len(transport.sent) != 1 {
		t.Fatalf("expected one outbound transport payload, got %d", len(transport.sent))
	}

	inboundPayload := []byte{5, 6, 7}
	if err := cm.HandleIncomingTransportPayload(context.Background(), callID, inboundPayload); err != nil {
		t.Fatalf("HandleIncomingTransportPayload failed: %v", err)
	}
	if len(engine.incoming) != 1 {
		t.Fatalf("expected one incoming payload in media engine, got %d", len(engine.incoming))
	}

	stats, ok := cm.GetMediaStats(callID)
	if !ok {
		t.Fatalf("expected media stats for call")
	}
	if stats.PacketsSent != 1 || stats.BytesSent != uint64(len(outboundPayload)) {
		t.Fatalf("unexpected outbound stats: %+v", stats)
	}
	if stats.PacketsReceived != 1 || stats.BytesReceived != uint64(len(inboundPayload)) {
		t.Fatalf("unexpected inbound stats: %+v", stats)
	}
	if stats.LastPacketSent.IsZero() || stats.LastPacketRecv.IsZero() {
		t.Fatalf("expected packet timestamps to be set: %+v", stats)
	}
}

func TestCallManagerStopMedia(t *testing.T) {
	cli := &Client{}
	cm := NewCallManager(cli)
	callID := "call-stop-media"
	cm.calls[callID] = &types.CallInfo{
		CallID:         callID,
		State:          types.CallStateConnecting,
		TransportState: types.TransportStateConnected,
	}
	cm.keys[callID] = &CallEncryptionKey{Generation: 1}

	engine := &testCallMediaEngine{}
	cm.SetMediaEngine(engine)

	if started, err := cm.StartMedia(context.Background(), callID); err != nil || !started {
		t.Fatalf("StartMedia failed: started=%v err=%v", started, err)
	}

	stopped, err := cm.StopMedia(context.Background(), callID)
	if err != nil {
		t.Fatalf("StopMedia failed: %v", err)
	}
	if !stopped {
		t.Fatalf("expected media to stop")
	}
	if engine.stopCalls != 1 {
		t.Fatalf("unexpected media engine stop calls: got %d want 1", engine.stopCalls)
	}

	info := cm.GetCall(callID)
	if info == nil {
		t.Fatalf("expected call info to exist")
	}
	if info.MediaState != types.MediaStateNone {
		t.Fatalf("unexpected media state after stop: %v", info.MediaState)
	}
	if info.MediaStoppedAt.IsZero() {
		t.Fatalf("expected MediaStoppedAt to be set")
	}

	stopped, err = cm.StopMedia(context.Background(), callID)
	if err != nil {
		t.Fatalf("unexpected second StopMedia error: %v", err)
	}
	if stopped {
		t.Fatalf("expected second StopMedia to be a no-op")
	}
	if engine.stopCalls != 1 {
		t.Fatalf("unexpected stop calls after second StopMedia: got %d want 1", engine.stopCalls)
	}
}

func TestCallManagerSetTransportRegistersIncomingHandler(t *testing.T) {
	cm := NewCallManager(&Client{})
	transport := &testCallTransport{}
	cm.SetTransport(transport)
	if transport.incoming == nil {
		t.Fatalf("expected SetTransport to register incoming handler")
	}
}

func TestCallManagerExpireStaleCalls(t *testing.T) {
	cm := NewCallManager(&Client{})
	callID := "call-timeout-1"
	cm.calls[callID] = &types.CallInfo{
		CallID:       callID,
		State:        types.CallStateRinging,
		RingDeadline: time.Now().Add(-time.Second),
	}

	expired := cm.ExpireStaleCalls(time.Now())
	if len(expired) != 1 || expired[0] != callID {
		t.Fatalf("unexpected expired list: %#v", expired)
	}
	info := cm.GetCall(callID)
	if info == nil {
		t.Fatalf("expected call info to exist")
	}
	if info.State != types.CallStateEnded {
		t.Fatalf("expected ended state after timeout, got %v", info.State)
	}
}

func TestCallManagerHandleRemoteAcceptFromInitiating(t *testing.T) {
	cm := NewCallManager(&Client{})
	callID := "call-accept-from-initiating"
	cm.calls[callID] = &types.CallInfo{
		CallID:         callID,
		State:          types.CallStateInitiating,
		TransportState: types.TransportStatePendingRelay,
		RingDeadline:   time.Now().Add(30 * time.Second),
	}

	cm.HandleRemoteAccept(&ParsedCallStanza{CallID: callID, From: types.NewJID("12345", types.HiddenUserServer)})

	info := cm.GetCall(callID)
	if info == nil {
		t.Fatalf("expected call info to exist")
	}
	if info.State != types.CallStateConnecting {
		t.Fatalf("expected call to move to connecting, got %v", info.State)
	}
	if info.AcceptedAt.IsZero() {
		t.Fatalf("expected AcceptedAt to be set")
	}
	if !info.RingDeadline.IsZero() {
		t.Fatalf("expected RingDeadline to be cleared")
	}
}

func TestCallManagerMarkOfferSentIsIdempotentForProgressedStates(t *testing.T) {
	for _, state := range []types.CallState{
		types.CallStateRinging,
		types.CallStateConnecting,
		types.CallStateActive,
	} {
		cm := NewCallManager(&Client{})
		callID := "call-mark-offer-idempotent"
		cm.calls[callID] = &types.CallInfo{
			CallID: callID,
			State:  state,
		}
		if err := cm.MarkOfferSent(callID); err != nil {
			t.Fatalf("expected MarkOfferSent to be idempotent for state %v, got error: %v", state, err)
		}
	}
}

func TestCallManagerHandleRemotePreAcceptExtendsOutgoingRingDeadline(t *testing.T) {
	cm := NewCallManager(&Client{})
	cm.SetRingTimeout(5 * time.Second)
	callID := "call-preaccept-extends-deadline"
	originalDeadline := time.Now().Add(2 * time.Second)
	cm.calls[callID] = &types.CallInfo{
		CallID:       callID,
		State:        types.CallStateRinging,
		IsInitiator:  true,
		RingDeadline: originalDeadline,
	}

	cm.HandleRemotePreAccept(&ParsedCallStanza{
		CallID: callID,
		From:   types.NewJID("12345", types.HiddenUserServer),
	})

	info := cm.GetCall(callID)
	if info == nil {
		t.Fatalf("expected call info to exist")
	}
	if !info.RingDeadline.After(originalDeadline) {
		t.Fatalf("expected ring deadline to be extended")
	}
	if remaining := time.Until(info.RingDeadline); remaining < minOutgoingPreAcceptGrace-time.Second {
		t.Fatalf("expected ring deadline grace >= %s, got %s", minOutgoingPreAcceptGrace, remaining)
	}
}

func TestCallManagerMarkOfferSentUsesMinimumOutgoingRingWindow(t *testing.T) {
	cm := NewCallManager(&Client{})
	cm.SetRingTimeout(5 * time.Second)
	callID := "call-mark-offer-min-outgoing-window"
	cm.calls[callID] = &types.CallInfo{
		CallID:      callID,
		State:       types.CallStateInitiating,
		IsInitiator: true,
	}

	start := time.Now()
	if err := cm.MarkOfferSent(callID); err != nil {
		t.Fatalf("MarkOfferSent failed: %v", err)
	}
	info := cm.GetCall(callID)
	if info == nil {
		t.Fatalf("expected call info")
	}
	remaining := info.RingDeadline.Sub(start)
	if remaining < minOutgoingRingTimeout-2*time.Second {
		t.Fatalf("expected outgoing ring window >= %s, got %s", minOutgoingRingTimeout, remaining)
	}
}

func TestCallManagerSendAudioAndVideoFrame(t *testing.T) {
	cm := NewCallManager(&Client{})
	callID := "call-frame-send"
	cm.calls[callID] = &types.CallInfo{
		CallID:         callID,
		State:          types.CallStateConnecting,
		TransportState: types.TransportStateConnected,
	}

	transport := &testCallTransport{}
	cm.SetTransport(transport)

	if err := cm.SendAudioFrame(context.Background(), callID, []byte("a1")); err != nil {
		t.Fatalf("SendAudioFrame failed: %v", err)
	}
	if err := cm.SendVideoFrame(context.Background(), callID, []byte("v1")); err != nil {
		t.Fatalf("SendVideoFrame failed: %v", err)
	}
	if len(transport.sent) != 2 {
		t.Fatalf("expected 2 framed payloads, got %d", len(transport.sent))
	}
	if len(transport.sent[0]) == 0 || MediaPayloadKind(transport.sent[0][0]) != MediaPayloadAudio {
		t.Fatalf("unexpected audio frame prefix")
	}
	if len(transport.sent[1]) == 0 || MediaPayloadKind(transport.sent[1][0]) != MediaPayloadVideo {
		t.Fatalf("unexpected video frame prefix")
	}
}

func TestCallManagerSendFrameUsesPacketizer(t *testing.T) {
	cm := NewCallManager(&Client{})
	callID := "call-packetizer"
	cm.calls[callID] = &types.CallInfo{
		CallID:         callID,
		State:          types.CallStateConnecting,
		TransportState: types.TransportStateConnected,
	}
	transport := &testCallTransport{}
	engine := &testPacketizingMediaEngine{}
	cm.SetTransport(transport)
	cm.SetMediaEngine(engine)

	if err := cm.SendAudioFrame(context.Background(), callID, []byte("audio-frame")); err != nil {
		t.Fatalf("SendAudioFrame failed: %v", err)
	}
	if len(transport.sent) != 1 {
		t.Fatalf("expected one sent payload, got %d", len(transport.sent))
	}
	if string(transport.sent[0]) != "rtp-a:"+callID+":audio-frame" {
		t.Fatalf("unexpected packetized payload: %q", transport.sent[0])
	}
}

func TestCallManagerDrainsMediaFeedback(t *testing.T) {
	cm := NewCallManager(&Client{})
	callID := "call-feedback"
	cm.calls[callID] = &types.CallInfo{
		CallID:         callID,
		State:          types.CallStateConnecting,
		TransportState: types.TransportStateConnected,
	}
	transport := &testCallTransport{}
	engine := &testPacketizingMediaEngine{
		feedback: map[string][][]byte{
			callID: {[]byte("rtcp-feedback-1"), []byte("rtcp-feedback-2")},
		},
	}
	cm.SetTransport(transport)
	cm.SetMediaEngine(engine)

	if err := cm.HandleIncomingTransportPayload(context.Background(), callID, []byte("inbound")); err != nil {
		t.Fatalf("HandleIncomingTransportPayload failed: %v", err)
	}
	if len(transport.sent) != 2 {
		t.Fatalf("expected drained feedback to be sent, got %d packets", len(transport.sent))
	}
}

func TestCallManagerMediaPump(t *testing.T) {
	cm := NewCallManager(&Client{})
	callID := "call-pump"
	cm.calls[callID] = &types.CallInfo{
		CallID:         callID,
		State:          types.CallStateConnecting,
		TransportState: types.TransportStateConnected,
	}
	transport := &testCallTransport{}
	engine := &testPacketizingMediaEngine{
		audioCh: make(chan []byte, 1),
	}
	transport.sendNotify = make(chan struct{}, 1)
	engine.audioCh <- []byte("pump-audio")
	cm.SetTransport(transport)
	cm.SetMediaEngine(engine)

	if err := cm.StartMediaIOPump(callID, 10*time.Millisecond); err != nil {
		t.Fatalf("StartMediaIOPump failed: %v", err)
	}
	defer cm.StopMediaIOPump(callID)

	select {
	case <-transport.sendNotify:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timed out waiting for pumped frame")
	}
}

func TestCallManagerTrimEndedCallsDropsOldestAndKeys(t *testing.T) {
	cm := NewCallManager(&Client{})
	cm.maxEndedCalls = 2

	oldest := time.Now().Add(-3 * time.Minute)
	middle := time.Now().Add(-2 * time.Minute)
	newest := time.Now().Add(-time.Minute)

	cm.calls["call-oldest"] = &types.CallInfo{
		CallID:        "call-oldest",
		State:         types.CallStateEnded,
		EndedAt:       oldest,
		OfferStanzaID: "offer-oldest",
	}
	cm.keys["call-oldest"] = &CallEncryptionKey{Generation: 1}
	cm.offerStanzaToCallID["offer-oldest"] = "call-oldest"

	cm.calls["call-middle"] = &types.CallInfo{
		CallID:        "call-middle",
		State:         types.CallStateEnded,
		EndedAt:       middle,
		OfferStanzaID: "offer-middle",
	}
	cm.keys["call-middle"] = &CallEncryptionKey{Generation: 1}
	cm.offerStanzaToCallID["offer-middle"] = "call-middle"

	cm.calls["call-newest"] = &types.CallInfo{
		CallID:        "call-newest",
		State:         types.CallStateEnded,
		EndedAt:       newest,
		OfferStanzaID: "offer-newest",
	}
	cm.keys["call-newest"] = &CallEncryptionKey{Generation: 1}
	cm.offerStanzaToCallID["offer-newest"] = "call-newest"

	cm.mu.Lock()
	cm.trimEndedCallsLocked()
	cm.mu.Unlock()

	if _, ok := cm.calls["call-oldest"]; ok {
		t.Fatalf("expected oldest ended call to be dropped")
	}
	if _, ok := cm.keys["call-oldest"]; ok {
		t.Fatalf("expected oldest call key to be dropped")
	}
	if _, ok := cm.offerStanzaToCallID["offer-oldest"]; ok {
		t.Fatalf("expected oldest offer mapping to be dropped")
	}
	if _, ok := cm.calls["call-middle"]; !ok {
		t.Fatalf("expected middle ended call to remain")
	}
	if _, ok := cm.calls["call-newest"]; !ok {
		t.Fatalf("expected newest ended call to remain")
	}
}

func TestCallManagerHoldAndResumeCall(t *testing.T) {
	cli := &Client{}
	cm := NewCallManager(cli)
	cli.callManager = cm

	callID := "call-hold-resume"
	engine := &testCallMediaEngine{}
	cm.SetMediaEngine(engine)
	cm.calls[callID] = &types.CallInfo{
		CallID:         callID,
		State:          types.CallStateActive,
		TransportState: types.TransportStateConnected,
		MediaState:     types.MediaStateActive,
	}
	cm.keys[callID] = &CallEncryptionKey{Generation: 1}

	if err := cm.HoldCall(context.Background(), callID); err != nil {
		t.Fatalf("HoldCall failed: %v", err)
	}
	info := cm.GetCall(callID)
	if info == nil || info.State != types.CallStateOnHold {
		t.Fatalf("expected call to be on hold, got %+v", info)
	}
	if engine.stopCalls != 1 {
		t.Fatalf("expected media stop to be called once, got %d", engine.stopCalls)
	}

	if err := cm.ResumeCall(context.Background(), callID); err != nil {
		t.Fatalf("ResumeCall failed: %v", err)
	}
	info = cm.GetCall(callID)
	if info == nil || info.State != types.CallStateActive {
		t.Fatalf("expected call to be active after resume, got %+v", info)
	}
	if engine.startCalls != 1 {
		t.Fatalf("expected media start to be called once, got %d", engine.startCalls)
	}
}

func TestCallManagerStoreEncryptionKeyZeroizesReplacedKey(t *testing.T) {
	cm := NewCallManager(&Client{})

	oldKey := &CallEncryptionKey{Generation: 3}
	for i := range oldKey.MasterKey {
		oldKey.MasterKey[i] = byte(i + 1)
	}
	newKey := &CallEncryptionKey{Generation: 4}
	for i := range newKey.MasterKey {
		newKey.MasterKey[i] = byte(0xA0 + i)
	}

	cm.StoreEncryptionKey("call-key-replace", oldKey)
	cm.StoreEncryptionKey("call-key-replace", newKey)

	if got := cm.GetEncryptionKey("call-key-replace"); got != newKey {
		t.Fatalf("expected new key pointer to be stored")
	}
	if oldKey.Generation != 0 {
		t.Fatalf("expected replaced key generation zeroized")
	}
	for _, b := range oldKey.MasterKey {
		if b != 0 {
			t.Fatalf("expected replaced key material to be zeroized")
		}
	}
}

func TestCallManagerCleanupCallZeroizesKey(t *testing.T) {
	cm := NewCallManager(&Client{})
	callID := "call-cleanup-zeroize"
	key := &CallEncryptionKey{Generation: 9}
	for i := range key.MasterKey {
		key.MasterKey[i] = byte(0xF0 - i)
	}
	cm.calls[callID] = &types.CallInfo{CallID: callID}
	cm.keys[callID] = key

	cm.CleanupCall(callID)

	if key.Generation != 0 {
		t.Fatalf("expected cleanup to zeroize generation")
	}
	for _, b := range key.MasterKey {
		if b != 0 {
			t.Fatalf("expected cleanup to zeroize key bytes")
		}
	}
}
