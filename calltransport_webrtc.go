// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"strings"
	"sync"
	"time"

	"go.mau.fi/whatsmeow/types"
)

// WebRTCRelaySession abstracts a single WebRTC data-path session.
//
// The initial milestone keeps this injected so we can land behavior parity
// (relay extraction + SDP semantics + manager integration) without forcing
// a concrete Pion dependency in one step.
type WebRTCRelaySession interface {
	Send(ctx context.Context, payload []byte) error
	Close(ctx context.Context) error
	SetIncomingHandler(handler func(payload []byte))
}

// WebRTCRelaySessionFactory constructs sessions for relay attempts.
type WebRTCRelaySessionFactory interface {
	NewSession(ctx context.Context, info *types.CallInfo, relay WebRTCRelayConnectionInfo) (WebRTCRelaySession, error)
}

// WebRTCRelaySessionFactoryFunc is a function adapter for WebRTCRelaySessionFactory.
type WebRTCRelaySessionFactoryFunc func(ctx context.Context, info *types.CallInfo, relay WebRTCRelayConnectionInfo) (WebRTCRelaySession, error)

// NewSession implements WebRTCRelaySessionFactory.
func (f WebRTCRelaySessionFactoryFunc) NewSession(ctx context.Context, info *types.CallInfo, relay WebRTCRelayConnectionInfo) (WebRTCRelaySession, error) {
	return f(ctx, info, relay)
}

// WebRTCRelayCallTransportConfig configures WebRTCRelayCallTransport.
type WebRTCRelayCallTransportConfig struct {
	SessionFactory WebRTCRelaySessionFactory
	ConnectTimeout time.Duration
	StateHandler   func(callID string, state WebRTCTransportState, reason error)
	// EnableCredentialVariantFallback enables non-parity credential permutations
	// for troubleshooting. Keep disabled for strict WAWeb parity behavior.
	EnableCredentialVariantFallback bool
}

// WebRTCRelayCallTransport is a WhatsApp-Web-style transport path that selects
// relay candidates using signaling metadata and delegates actual WebRTC session
// establishment to an injected backend.
type WebRTCRelayCallTransport struct {
	cfg      WebRTCRelayCallTransportConfig
	incoming IncomingCallTransportPayloadHandler

	mu      sync.RWMutex
	session map[string]WebRTCRelaySession
	relay   map[string]WebRTCRelayConnectionInfo
	state   map[string]WebRTCTransportState
}

const defaultWebRTCRelayConnectTimeout = 12 * time.Second
const remoteAcceptRelayGroupConnectTimeout = 12 * time.Second

// NewWebRTCRelayCallTransport creates a new WebRTC relay transport adapter.
func NewWebRTCRelayCallTransport(cfg WebRTCRelayCallTransportConfig) *WebRTCRelayCallTransport {
	return &WebRTCRelayCallTransport{
		cfg:     cfg,
		session: make(map[string]WebRTCRelaySession),
		relay:   make(map[string]WebRTCRelayConnectionInfo),
		state:   make(map[string]WebRTCTransportState),
	}
}

// SetIncomingHandler sets the inbound payload callback.
func (t *WebRTCRelayCallTransport) SetIncomingHandler(handler IncomingCallTransportPayloadHandler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.incoming = handler
	for callID, sess := range t.session {
		sess.SetIncomingHandler(t.wrapIncomingHandler(callID))
	}
}

// Connect opens a WebRTC data path for the call by trying relay groups in
// ascending c2r-rtt order. Multiple addresses for the same relay ID are
// attempted in parallel before falling back to the next relay ID.
func (t *WebRTCRelayCallTransport) Connect(ctx context.Context, info *types.CallInfo) error {
	if info == nil {
		return fmt.Errorf("call info is nil")
	}
	if info.CallID == "" {
		return fmt.Errorf("call id is required")
	}

	t.mu.RLock()
	if _, ok := t.session[info.CallID]; ok {
		t.mu.RUnlock()
		return nil
	}
	t.mu.RUnlock()

	if t.cfg.SessionFactory == nil {
		return fmt.Errorf("webrtc session factory is not configured")
	}

	relays, err := ExtractWebRTCRelayConnectionInfo(info.RelayData)
	if err != nil {
		t.setStateWithReason(info.CallID, WebRTCTransportStateFailed, err)
		return err
	}
	attemptID, source := callTransportAttemptTraceFromContext(ctx)
	if attemptID == "" {
		attemptID = "unknown"
	}
	if source == "" {
		source = "unknown"
	}
	if t.cfg.EnableCredentialVariantFallback && (source == "remote_accept" || source == "offer_ack") {
		relays = ExpandWebRTCRelayCredentialVariants(relays)
	}

	t.setState(info.CallID, WebRTCTransportStateCreatingOffer)

	relayGroups := groupWebRTCRelaysByPriority(relays)
	groupTimeout := resolveRelayGroupConnectTimeout(t.cfg.ConnectTimeout, source)

	// WAWeb creates all PeerConnections in parallel (one per relay address).
	// Always try all relay groups in parallel for fastest connection.
	groupLabels := make([]string, 0, len(relayGroups))
	for _, group := range relayGroups {
		groupLabels = append(groupLabels, describeRelayGroup(group))
	}
	t.setStateWithReason(
		info.CallID,
		WebRTCTransportStateConnecting,
		fmt.Errorf("attempt=%s source=%s attempting relay groups in parallel: %s", attemptID, source, strings.Join(groupLabels, " | ")),
	)

	relay, sess, groupErrors := t.connectRelayGroupsInParallel(ctx, info, relayGroups, groupTimeout, attemptID, source)
	if sess != nil {
		t.mu.Lock()
		if _, exists := t.session[info.CallID]; exists {
			t.mu.Unlock()
			_ = sess.Close(ctx)
			return nil
		}
		t.session[info.CallID] = sess
		t.relay[info.CallID] = relay
		t.mu.Unlock()

		sess.SetIncomingHandler(t.wrapIncomingHandler(info.CallID))
		t.setState(info.CallID, WebRTCTransportStateConnected)
		return nil
	}
	if len(groupErrors) > 0 {
		joined := errors.Join(groupErrors...)
		t.setStateWithReason(info.CallID, WebRTCTransportStateFailed, joined)
		return fmt.Errorf("failed to connect to any relay: %w", joined)
	}
	t.setStateWithReason(info.CallID, WebRTCTransportStateFailed, nil)
	return fmt.Errorf("failed to connect to any relay")
}

type webRTCRelayConnectResult struct {
	relay   WebRTCRelayConnectionInfo
	session WebRTCRelaySession
	err     error
}

type webRTCRelayGroupConnectResult struct {
	groupDesc string
	relay     WebRTCRelayConnectionInfo
	session   WebRTCRelaySession
	err       error
}

func resolveRelayGroupConnectTimeout(configured time.Duration, source string) time.Duration {
	timeout := configured
	if timeout <= 0 {
		timeout = defaultWebRTCRelayConnectTimeout
	}
	if source == "remote_accept" && timeout > remoteAcceptRelayGroupConnectTimeout {
		return remoteAcceptRelayGroupConnectTimeout
	}
	return timeout
}

func (t *WebRTCRelayCallTransport) connectRelayGroupsInParallel(
	ctx context.Context,
	info *types.CallInfo,
	groups [][]WebRTCRelayConnectionInfo,
	timeout time.Duration,
	attemptID string,
	source string,
) (WebRTCRelayConnectionInfo, WebRTCRelaySession, []error) {
	if len(groups) == 0 {
		return WebRTCRelayConnectionInfo{}, nil, nil
	}
	if timeout <= 0 {
		timeout = defaultWebRTCRelayConnectTimeout
	}

	parallelCtx, cancelParallel := context.WithCancel(ctx)
	defer cancelParallel()

	results := make(chan webRTCRelayGroupConnectResult, len(groups))
	for _, group := range groups {
		groupCopy := append([]WebRTCRelayConnectionInfo(nil), group...)
		groupDesc := describeRelayGroup(groupCopy)
		go func() {
			relay, sess, err := t.connectRelayGroup(parallelCtx, info, groupCopy, timeout)
			if err != nil {
				results <- webRTCRelayGroupConnectResult{
					groupDesc: groupDesc,
					err:       fmt.Errorf("attempt=%s source=%s relay group %s failed: %w", attemptID, source, groupDesc, err),
				}
				return
			}
			results <- webRTCRelayGroupConnectResult{
				groupDesc: groupDesc,
				relay:     relay,
				session:   sess,
			}
		}()
	}

	var (
		winnerRelay   WebRTCRelayConnectionInfo
		winnerSession WebRTCRelaySession
		groupErrors   []error
	)
	for i := 0; i < len(groups); i++ {
		result := <-results
		if result.err != nil {
			groupErrors = append(groupErrors, result.err)
			continue
		}
		if result.session == nil {
			groupErrors = append(groupErrors, fmt.Errorf("attempt=%s source=%s relay group %s failed: nil session", attemptID, source, result.groupDesc))
			continue
		}
		if winnerSession == nil {
			winnerRelay = result.relay
			winnerSession = result.session
			cancelParallel()
			continue
		}
		_ = result.session.Close(context.Background())
	}

	if winnerSession != nil {
		return winnerRelay, winnerSession, groupErrors
	}
	return WebRTCRelayConnectionInfo{}, nil, groupErrors
}

func (t *WebRTCRelayCallTransport) connectRelayGroup(ctx context.Context, info *types.CallInfo, group []WebRTCRelayConnectionInfo, timeout time.Duration) (WebRTCRelayConnectionInfo, WebRTCRelaySession, error) {
	if len(group) == 0 {
		return WebRTCRelayConnectionInfo{}, nil, fmt.Errorf("relay group is empty")
	}

	if timeout <= 0 {
		timeout = defaultWebRTCRelayConnectTimeout
	}

	groupCtx, cancelGroup := context.WithCancel(ctx)
	defer cancelGroup()

	results := make(chan webRTCRelayConnectResult, len(group))
	for _, relay := range group {
		relay := relay
		go func() {
			if err := groupCtx.Err(); err != nil {
				results <- webRTCRelayConnectResult{relay: relay, err: err}
				return
			}
			attemptCtx, cancelAttempt := context.WithTimeout(groupCtx, timeout)
			defer cancelAttempt()
			sess, err := t.cfg.SessionFactory.NewSession(attemptCtx, info, relay)
			if err != nil {
				results <- webRTCRelayConnectResult{relay: relay, err: err}
				return
			}
			if sess == nil {
				results <- webRTCRelayConnectResult{relay: relay, err: fmt.Errorf("session factory returned nil session")}
				return
			}
			select {
			case results <- webRTCRelayConnectResult{relay: relay, session: sess}:
			case <-groupCtx.Done():
				_ = sess.Close(context.Background())
			}
		}()
	}

	var (
		winnerRelay   WebRTCRelayConnectionInfo
		winnerSession WebRTCRelaySession
		attemptErrs   []error
	)
	for range group {
		result := <-results
		if result.err != nil {
			attemptErrs = append(attemptErrs, fmt.Errorf("%s(%s:%d): %w", result.relay.RelayName, result.relay.IP, result.relay.Port, result.err))
			continue
		}
		if winnerSession == nil {
			winnerRelay = result.relay
			winnerSession = result.session
			cancelGroup()
			continue
		}
		_ = result.session.Close(context.Background())
	}

	if winnerSession != nil {
		return winnerRelay, winnerSession, nil
	}
	if len(attemptErrs) > 0 {
		return WebRTCRelayConnectionInfo{}, nil, errors.Join(attemptErrs...)
	}
	return WebRTCRelayConnectionInfo{}, nil, fmt.Errorf("failed to connect to relay group")
}

func groupWebRTCRelaysByPriority(relays []WebRTCRelayConnectionInfo) [][]WebRTCRelayConnectionInfo {
	if len(relays) == 0 {
		return nil
	}
	groups := make([][]WebRTCRelayConnectionInfo, 0, len(relays))
	groupByRelayID := make(map[uint32]int, len(relays))
	for _, relay := range relays {
		idx, ok := groupByRelayID[relay.RelayID]
		if !ok {
			idx = len(groups)
			groupByRelayID[relay.RelayID] = idx
			groups = append(groups, nil)
		}
		groups[idx] = append(groups[idx], relay)
	}
	return groups
}

// Send writes a payload to the active WebRTC data path for a call.
func (t *WebRTCRelayCallTransport) Send(ctx context.Context, info *types.CallInfo, payload []byte) error {
	if info == nil {
		return fmt.Errorf("call info is nil")
	}
	if len(payload) == 0 {
		return nil
	}

	t.mu.RLock()
	sess := t.session[info.CallID]
	t.mu.RUnlock()
	if sess == nil {
		return fmt.Errorf("call %s transport is not connected", info.CallID)
	}
	return sess.Send(ctx, payload)
}

// Close tears down a call's active WebRTC session.
func (t *WebRTCRelayCallTransport) Close(ctx context.Context, info *types.CallInfo) error {
	if info == nil {
		return nil
	}

	t.mu.Lock()
	sess := t.session[info.CallID]
	delete(t.session, info.CallID)
	delete(t.relay, info.CallID)
	t.state[info.CallID] = WebRTCTransportStateClosed
	handler := t.cfg.StateHandler
	t.mu.Unlock()
	if handler != nil {
		handler(info.CallID, WebRTCTransportStateClosed, nil)
	}

	if sess == nil {
		return nil
	}
	return sess.Close(ctx)
}

// State returns the current transport state for a call.
func (t *WebRTCRelayCallTransport) State(callID string) WebRTCTransportState {
	t.mu.RLock()
	defer t.mu.RUnlock()
	state, ok := t.state[callID]
	if !ok {
		return WebRTCTransportStateIdle
	}
	return state
}

// ConnectedRelay returns the selected relay for a connected call.
func (t *WebRTCRelayCallTransport) ConnectedRelay(callID string) (WebRTCRelayConnectionInfo, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	relay, ok := t.relay[callID]
	return relay, ok
}

func (t *WebRTCRelayCallTransport) setState(callID string, state WebRTCTransportState) {
	t.setStateWithReason(callID, state, nil)
}

func (t *WebRTCRelayCallTransport) setStateWithReason(callID string, state WebRTCTransportState, reason error) {
	t.mu.Lock()
	t.state[callID] = state
	handler := t.cfg.StateHandler
	t.mu.Unlock()
	if handler != nil {
		handler(callID, state, reason)
	}
}

// SetStateHandler configures an observer for transport state transitions.
func (t *WebRTCRelayCallTransport) SetStateHandler(handler func(callID string, state WebRTCTransportState, reason error)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cfg.StateHandler = handler
}

func (t *WebRTCRelayCallTransport) wrapIncomingHandler(callID string) func(payload []byte) {
	return func(payload []byte) {
		if len(payload) == 0 {
			return
		}
		t.mu.RLock()
		handler := t.incoming
		t.mu.RUnlock()
		if handler == nil {
			return
		}
		copied := make([]byte, len(payload))
		copy(copied, payload)
		handler(callID, copied)
	}
}

func describeRelayGroup(group []WebRTCRelayConnectionInfo) string {
	if len(group) == 0 {
		return "<empty>"
	}
	parts := make([]string, 0, len(group))
	for _, relay := range group {
		credTag := shortRelayCredentialFingerprint(relay)
		if credTag != "" {
			parts = append(parts, fmt.Sprintf("%s#%d@%s:%d[%s]", relay.RelayName, relay.RelayID, relay.IP, relay.Port, credTag))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s#%d@%s:%d", relay.RelayName, relay.RelayID, relay.IP, relay.Port))
	}
	return strings.Join(parts, ",")
}

func shortRelayCredentialFingerprint(relay WebRTCRelayConnectionInfo) string {
	if relay.AuthToken == "" || relay.RelayKey == "" {
		return ""
	}
	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(relay.AuthToken))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(relay.RelayKey))
	return fmt.Sprintf("cred:%08x", hasher.Sum32())
}
