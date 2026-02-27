// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

// CallManager manages active calls and their state transitions.
type CallManager struct {
	cli                  *Client
	calls                map[string]*types.CallInfo
	keys                 map[string]*CallEncryptionKey
	offerStanzaToCallID  map[string]string
	transportAttempts    map[string]transportAttemptRuntime
	relayByPeer          map[string]*types.RelayData
	offerProfileByPeer   map[string]*types.CallOfferExtensions
	lastRelayData        *types.RelayData
	lastOfferProfile     *types.CallOfferExtensions
	offerProfileProvider CallOfferProfileProvider
	relayAllocator       CallRelayAllocator
	transport            CallTransport
	mediaEngine          CallMediaEngine
	mediaPumpCancels     map[string]context.CancelFunc
	mediaPumpInterval    time.Duration
	ringTimeout          time.Duration
	maxEndedCalls        int
	mu                   sync.RWMutex
}

type transportAttemptRuntime struct {
	attemptID string
	cancel    context.CancelFunc
	source    string
	startedAt time.Time
}

const (
	minOutgoingPreAcceptGrace = 15 * time.Second
	minOutgoingRingTimeout    = 90 * time.Second
	remoteAcceptPreemptAfter  = 3 * time.Second
)

// NewCallManager creates a new CallManager attached to a Client.
func NewCallManager(cli *Client) *CallManager {
	cm := &CallManager{
		cli:                 cli,
		calls:               make(map[string]*types.CallInfo),
		keys:                make(map[string]*CallEncryptionKey),
		offerStanzaToCallID: make(map[string]string),
		transportAttempts:   make(map[string]transportAttemptRuntime),
		relayByPeer:         make(map[string]*types.RelayData),
		offerProfileByPeer:  make(map[string]*types.CallOfferExtensions),
		transport:           newDefaultCallTransport(),
		mediaEngine:         newDefaultCallMediaEngine(),
		mediaPumpCancels:    make(map[string]context.CancelFunc),
		mediaPumpInterval:   20 * time.Millisecond,
		ringTimeout:         45 * time.Second,
		maxEndedCalls:       128,
	}
	cm.transport.SetIncomingHandler(cm.handleTransportIncomingPayload)
	return cm
}

// GetCall returns the CallInfo for the given call ID, or nil if not found.
func (cm *CallManager) GetCall(callID string) *types.CallInfo {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.calls[callID]
}

// GetCallStateSnapshot returns the current call and transport state for a call ID.
func (cm *CallManager) GetCallStateSnapshot(callID string) (types.CallState, types.TransportState, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	info, ok := cm.calls[callID]
	if !ok || info == nil {
		return types.CallStateEnded, types.TransportStateNone, false
	}
	return info.State, info.TransportState, true
}

// GetActiveCall returns the first call that is not in the Ended state.
func (cm *CallManager) GetActiveCall() *types.CallInfo {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	for _, info := range cm.calls {
		if info.State != types.CallStateEnded {
			return info
		}
	}
	return nil
}

// getNonEndedCallIDsByPeer returns call IDs that are not ended for the given
// peer (normalized to PN/LID bare JID).
func (cm *CallManager) getNonEndedCallIDsByPeer(peer types.JID) []string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	key := normalizeCallPeerJID(peer)
	callIDs := make([]string, 0, len(cm.calls))
	for callID, info := range cm.calls {
		if info == nil || info.State == types.CallStateEnded {
			continue
		}
		if key != "" && normalizeCallPeerJID(info.PeerJID) != key {
			continue
		}
		callIDs = append(callIDs, callID)
	}
	sort.Strings(callIDs)
	return callIDs
}

// StartCall creates a new outgoing call and returns the CallInfo.
// The caller should then encrypt the call key and send the offer stanza.
func (cm *CallManager) StartCall(ctx context.Context, peerJID types.JID, options types.CallOptions) (*types.CallInfo, *CallEncryptionKey, error) {
	resolvedPeerJID := cm.resolveCallSignalingPeerJID(ctx, peerJID)

	callID, err := generateWhatsAppCallID()
	if err != nil {
		return nil, nil, err
	}
	ownID := cm.cli.getOwnIDForCallPeer(resolvedPeerJID)
	if ownID.IsEmpty() {
		return nil, nil, ErrNotLoggedIn
	}

	info := &types.CallInfo{
		CallID:          callID,
		PeerJID:         resolvedPeerJID,
		CallCreator:     ownID,
		CallerPN:        types.EmptyJID,
		GroupJID:        options.GroupJID,
		State:           types.CallStateInitiating,
		IsVideo:         options.Video,
		IsInitiator:     true,
		StartedAt:       time.Now(),
		OfferExtensions: nil,
	}

	var (
		relayAllocator       CallRelayAllocator
		offerProfileProvider CallOfferProfileProvider
	)
	cm.mu.RLock()
	offerProfileProvider = cm.offerProfileProvider
	relayAllocator = cm.relayAllocator
	if options.RelayData != nil {
		info.RelayData = cloneRelayData(options.RelayData)
	}
	// NOTE: We intentionally do NOT pre-populate info.RelayData from the peer
	// relay cache for outgoing offers. WAWeb never sends <relay> in the outgoing
	// offer — the server allocates relay and returns it in the offer ACK. Using
	// cached relay data from a previous call would include stale auth tokens and
	// UUIDs that the server would reject, breaking the second+ call attempt.
	cm.mu.RUnlock()

	var providedOfferProfile *types.CallOfferExtensions
	if options.OfferExtensions == nil && offerProfileProvider != nil {
		providedOfferProfile, err = offerProfileProvider.GetCallOfferExtensions(ctx, info)
		if err != nil {
			return nil, nil, fmt.Errorf("pre-offer profile generation failed: %w", err)
		}
	}
	info.OfferExtensions = cm.buildOutgoingOfferExtensions(options.OfferExtensions, providedOfferProfile)

	if info.RelayData == nil && relayAllocator != nil {
		allocatedRelay, allocErr := relayAllocator.AllocateRelayData(ctx, info)
		if allocErr != nil {
			return nil, nil, fmt.Errorf("pre-offer relay allocation failed: %w", allocErr)
		}
		info.RelayData = cloneRelayData(allocatedRelay)
	}

	key, err := GenerateCallKey()
	if err != nil {
		return nil, nil, err
	}

	cm.mu.Lock()
	cm.calls[callID] = info
	cm.keys[callID] = &key
	if info.RelayData != nil {
		cm.cacheRelayDataForPeerLocked(info.PeerJID, info.RelayData)
	}
	if info.OfferExtensions != nil && (options.OfferExtensions != nil || providedOfferProfile != nil) {
		cm.cacheOfferProfileForPeerLocked(info.PeerJID, info.OfferExtensions)
	}
	cm.mu.Unlock()

	return info, &key, nil
}

func (cm *CallManager) resolveCallSignalingPeerJID(ctx context.Context, peerJID types.JID) types.JID {
	if ctx == nil {
		ctx = context.Background()
	}
	if peerJID.Server != types.DefaultUserServer || cm == nil || cm.cli == nil || cm.cli.Store == nil || cm.cli.Store.LIDs == nil {
		return peerJID.ToNonAD()
	}

	lookupPN := peerJID.ToNonAD()
	lid, err := cm.cli.Store.LIDs.GetLIDForPN(ctx, lookupPN)
	if err != nil {
		if cm.cli.Log != nil {
			cm.cli.Log.Warnf("Failed to resolve LID for call signaling peer %s: %v", peerJID, err)
		}
		return peerJID.ToNonAD()
	}
	if lid.IsEmpty() {
		return peerJID.ToNonAD()
	}
	cm.cli.migrateSessionStore(ctx, peerJID, lid)
	return lid.ToNonAD()
}

func generateWhatsAppCallID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", fmt.Errorf("failed to generate call id: %w", err)
	}
	return strings.ToUpper(hex.EncodeToString(bytes[:])), nil
}

func cloneCallOfferExtensions(in *types.CallOfferExtensions) *types.CallOfferExtensions {
	if in == nil {
		return nil
	}
	out := *in
	if len(in.Privacy) > 0 {
		out.Privacy = append([]byte(nil), in.Privacy...)
	}
	if len(in.Capability) > 0 {
		out.Capability = append([]byte(nil), in.Capability...)
	}
	if len(in.RTE) > 0 {
		out.RTE = append([]byte(nil), in.RTE...)
	}
	if in.Metadata != nil {
		metadata := *in.Metadata
		out.Metadata = &metadata
	}
	return &out
}

func cloneVoIPSettingsByJID(in map[types.JID]string) map[types.JID]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[types.JID]string, len(in))
	for jid, value := range in {
		out[jid.ToNonAD()] = value
	}
	return out
}

func cloneUserDevicesByJID(in map[types.JID][]types.JID) map[types.JID][]types.JID {
	if len(in) == 0 {
		return nil
	}
	out := make(map[types.JID][]types.JID, len(in))
	for jid, devices := range in {
		user := jid.ToNonAD()
		copied := make([]types.JID, 0, len(devices))
		for _, device := range devices {
			copied = append(copied, device.ToNonAD())
		}
		out[user] = copied
	}
	return out
}

func selectAckVoIPSettingsForPeer(peer types.JID, voipByJID map[types.JID]string) string {
	if len(voipByJID) == 0 {
		return ""
	}
	peer = peer.ToNonAD()
	if value, ok := voipByJID[peer]; ok && value != "" {
		return value
	}
	for jid, value := range voipByJID {
		if value == "" {
			continue
		}
		if jid.User == peer.User && jid.Server == peer.Server {
			return value
		}
	}
	for _, value := range voipByJID {
		if value != "" {
			return value
		}
	}
	return ""
}

func cloneRelayData(in *types.RelayData) *types.RelayData {
	if in == nil {
		return nil
	}
	out := &types.RelayData{
		AttributePadding: in.AttributePadding,
		HBHKey:           append([]byte(nil), in.HBHKey...),
		RelayKey:         append([]byte(nil), in.RelayKey...),
		UUID:             in.UUID,
		SelfPID:          in.SelfPID,
		PeerPID:          in.PeerPID,
	}
	if len(in.Participants) > 0 {
		out.Participants = append([]types.RelayParticipant(nil), in.Participants...)
	}
	if len(in.RelayTokens) > 0 {
		out.RelayTokens = make([][]byte, len(in.RelayTokens))
		for i := range in.RelayTokens {
			out.RelayTokens[i] = append([]byte(nil), in.RelayTokens[i]...)
		}
	}
	if len(in.AuthTokens) > 0 {
		out.AuthTokens = make([][]byte, len(in.AuthTokens))
		for i := range in.AuthTokens {
			out.AuthTokens[i] = append([]byte(nil), in.AuthTokens[i]...)
		}
	}
	if len(in.Endpoints) > 0 {
		out.Endpoints = make([]types.RelayEndpoint, len(in.Endpoints))
		for i := range in.Endpoints {
			out.Endpoints[i] = in.Endpoints[i]
			if in.Endpoints[i].C2RRTTMs != nil {
				c2r := *in.Endpoints[i].C2RRTTMs
				out.Endpoints[i].C2RRTTMs = &c2r
			}
			if len(in.Endpoints[i].Addresses) > 0 {
				out.Endpoints[i].Addresses = append([]types.RelayAddress(nil), in.Endpoints[i].Addresses...)
			}
		}
	}
	return out
}

func normalizeCallPeerJID(peer types.JID) string {
	return peer.ToNonAD().String()
}

func (cm *CallManager) cacheRelayDataForPeerLocked(peer types.JID, relayData *types.RelayData) {
	if relayData == nil {
		return
	}
	cloned := cloneRelayData(relayData)
	cm.relayByPeer[normalizeCallPeerJID(peer)] = cloned
	cm.lastRelayData = cloneRelayData(cloned)
}

func (cm *CallManager) getCachedRelayDataForPeerLocked(peer types.JID) *types.RelayData {
	if relay := cm.relayByPeer[normalizeCallPeerJID(peer)]; relay != nil {
		return cloneRelayData(relay)
	}
	return cloneRelayData(cm.lastRelayData)
}

func (cm *CallManager) cacheOfferProfileForPeerLocked(peer types.JID, offer *types.CallOfferExtensions) {
	if offer == nil {
		return
	}
	key := normalizeCallPeerJID(peer)
	cm.offerProfileByPeer[key] = mergeOfferProfile(cm.offerProfileByPeer[key], offer)
	cm.lastOfferProfile = mergeOfferProfile(cm.lastOfferProfile, offer)
}

func (cm *CallManager) getCachedOfferProfileForPeerLocked(peer types.JID) *types.CallOfferExtensions {
	if offer := cm.offerProfileByPeer[normalizeCallPeerJID(peer)]; offer != nil {
		return cloneCallOfferExtensions(offer)
	}
	return cloneCallOfferExtensions(cm.lastOfferProfile)
}

func (cm *CallManager) buildOutgoingOfferExtensions(explicit, provided *types.CallOfferExtensions) *types.CallOfferExtensions {
	out := cloneCallOfferExtensions(explicit)
	if out == nil {
		out = cloneCallOfferExtensions(provided)
	}
	if out == nil {
		out = &types.CallOfferExtensions{}
	}

	if len(out.Capability) == 0 {
		out.Capability = append([]byte(nil), defaultCapability...)
	}
	// RTE is nonce-like and should only be used when provided by caller/profile.
	// Do not auto-fill RTE, joinable, uploadfieldstat or caller country defaults.

	return out
}

func mergeOfferProfile(base, update *types.CallOfferExtensions) *types.CallOfferExtensions {
	if update == nil {
		out := cloneCallOfferExtensions(base)
		if out != nil {
			out.RTE = nil
		}
		return out
	}
	if base == nil {
		out := cloneCallOfferExtensions(update)
		if out != nil {
			out.RTE = nil
		}
		return out
	}

	out := cloneCallOfferExtensions(base)
	if update.Joinable {
		out.Joinable = true
	}
	if update.CallerCountryCode != "" {
		out.CallerCountryCode = update.CallerCountryCode
	}
	if len(update.Capability) > 0 {
		out.Capability = append([]byte(nil), update.Capability...)
	}
	if len(update.Privacy) > 0 {
		out.Privacy = append([]byte(nil), update.Privacy...)
	}
	if update.Metadata != nil {
		metadata := *update.Metadata
		out.Metadata = &metadata
	}
	if update.UploadFieldStat {
		out.UploadFieldStat = true
	}
	if update.VoIPSettings != "" {
		out.VoIPSettings = update.VoIPSettings
	}
	// RTE is nonce-like and should not be cached/replayed across calls.
	out.RTE = nil
	return out
}

// MarkOfferSent transitions an outgoing call from Initiating to Ringing.
func (cm *CallManager) MarkOfferSent(callID string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	info, ok := cm.calls[callID]
	if !ok {
		return fmt.Errorf("call %s not found", callID)
	}
	// Accept/preaccept can arrive very quickly and move state forward before the
	// sender goroutine marks the offer as sent. Treat progressed states as
	// idempotent success instead of failing StartCall with a race.
	if info.State == types.CallStateRinging || info.State == types.CallStateConnecting || info.State == types.CallStateActive {
		return nil
	}
	if info.State != types.CallStateInitiating {
		return fmt.Errorf("call %s in wrong state %d for MarkOfferSent", callID, info.State)
	}
	info.State = types.CallStateRinging
	info.RingDeadline = time.Now().Add(cm.outgoingRingWindowLocked(info))
	return nil
}

// RegisterIncomingCall stores information about an incoming call from a parsed offer stanza.
func (cm *CallManager) RegisterIncomingCall(parsed *ParsedCallStanza) (*types.CallInfo, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if _, exists := cm.calls[parsed.CallID]; exists {
		return cm.calls[parsed.CallID], nil
	}

	info := &types.CallInfo{
		CallID:          parsed.CallID,
		PeerJID:         parsed.From,
		CallCreator:     parsed.CallCreator,
		CallerPN:        parsed.CallerPN,
		GroupJID:        parsed.GroupJID,
		State:           types.CallStateIncomingRinging,
		IsVideo:         parsed.IsVideo,
		IsInitiator:     false,
		StartedAt:       time.Now(),
		MediaParams:     parsed.MediaParams,
		RelayData:       cloneRelayData(parsed.RelayData),
		OfferEncData:    parsed.OfferEncData,
		OfferExtensions: cloneCallOfferExtensions(parsed.OfferExtensions),
		TransportState:  types.TransportStatePendingRelay,
		RingDeadline:    time.Now().Add(cm.ringTimeout),
	}
	cm.cacheRelayDataForPeerLocked(parsed.From, info.RelayData)
	cm.cacheOfferProfileForPeerLocked(parsed.From, info.OfferExtensions)

	cm.calls[parsed.CallID] = info
	return info, nil
}

// SetTransport sets the CallTransport implementation used for Phase 2 transport setup.
func (cm *CallManager) SetTransport(transport CallTransport) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if transport == nil {
		cm.transport = newDefaultCallTransport()
		cm.transport.SetIncomingHandler(cm.handleTransportIncomingPayload)
		return
	}
	cm.transport = transport
	cm.transport.SetIncomingHandler(cm.handleTransportIncomingPayload)
}

// SetRelayAllocator sets an optional pre-offer relay allocator used to enrich
// outgoing offers with relay/auth data before sending.
func (cm *CallManager) SetRelayAllocator(allocator CallRelayAllocator) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.relayAllocator = allocator
}

// SetOfferProfileProvider sets an optional pre-offer profile provider used to
// enrich outgoing offers with voip/capability metadata when explicit options
// are not set.
func (cm *CallManager) SetOfferProfileProvider(provider CallOfferProfileProvider) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.offerProfileProvider = provider
}

// SetMediaEngine sets the CallMediaEngine implementation used for Phase 3 media handling.
func (cm *CallManager) SetMediaEngine(engine CallMediaEngine) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if engine == nil {
		cm.mediaEngine = newDefaultCallMediaEngine()
		return
	}
	cm.mediaEngine = engine
}

// SetMediaIO configures media IO adapters on engines that support IO configuration.
func (cm *CallManager) SetMediaIO(io CallMediaIO) {
	cm.mu.Lock()
	engine := cm.mediaEngine
	cm.mu.Unlock()
	if configurable, ok := engine.(CallMediaIOConfigurable); ok {
		configurable.SetMediaIO(io)
	}
}

// SetRingTimeout configures ringing timeout for outgoing and incoming ringing calls.
func (cm *CallManager) SetRingTimeout(timeout time.Duration) {
	if timeout <= 0 {
		return
	}
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.ringTimeout = timeout
}

// SetMediaPumpInterval configures the default media pump tick interval.
func (cm *CallManager) SetMediaPumpInterval(interval time.Duration) {
	if interval <= 0 {
		return
	}
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.mediaPumpInterval = interval
}

// TrackOutgoingOffer links an outgoing offer stanza ID to a call ID.
func (cm *CallManager) TrackOutgoingOffer(callID, stanzaID string) error {
	if stanzaID == "" {
		return fmt.Errorf("stanza id is required")
	}
	cm.mu.Lock()
	defer cm.mu.Unlock()
	info, ok := cm.calls[callID]
	if !ok {
		return fmt.Errorf("call %s not found", callID)
	}
	info.OfferStanzaID = stanzaID
	cm.offerStanzaToCallID[stanzaID] = callID
	info.TransportState = types.TransportStatePendingRelay
	return nil
}

// ResolveCallIDByOfferStanzaID resolves a call ID for a previously tracked outgoing offer stanza ID.
func (cm *CallManager) ResolveCallIDByOfferStanzaID(stanzaID string) (string, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	callID, ok := cm.offerStanzaToCallID[stanzaID]
	return callID, ok
}

// HandleOfferAck stores relay allocation and enrichment data received from server offer ACK.
func (cm *CallManager) HandleOfferAck(callID string, ack *ParsedOfferAckData) error {
	if ack == nil {
		return fmt.Errorf("offer ack data is nil")
	}
	cm.mu.Lock()
	defer cm.mu.Unlock()
	info, ok := cm.calls[callID]
	if !ok {
		return fmt.Errorf("call %s not found", callID)
	}

	if ack.RelayData != nil {
		info.RelayData = cloneRelayData(ack.RelayData)
		info.RelayAllocatedAt = time.Now()
		cm.cacheRelayDataForPeerLocked(info.PeerJID, info.RelayData)
		if info.TransportState == types.TransportStateNone {
			info.TransportState = types.TransportStatePendingRelay
		}
	}

	info.OfferAckRTE = append([]byte(nil), ack.RTE...)
	info.OfferAckVoIPByJID = cloneVoIPSettingsByJID(ack.VoIPSettingsByJID)
	info.OfferAckDevices = cloneUserDevicesByJID(ack.UserDevices)

	ackProfile := &types.CallOfferExtensions{
		Joinable:        ack.Joinable,
		UploadFieldStat: ack.HasUploadFieldStat,
		RTE:             append([]byte(nil), ack.RTE...),
	}
	ackProfile.VoIPSettings = selectAckVoIPSettingsForPeer(info.PeerJID, ack.VoIPSettingsByJID)
	if !ackProfile.Joinable && !ackProfile.UploadFieldStat && len(ackProfile.RTE) == 0 && ackProfile.VoIPSettings == "" {
		return nil
	}
	info.OfferExtensions = mergeOfferProfile(info.OfferExtensions, ackProfile)
	cm.cacheOfferProfileForPeerLocked(info.PeerJID, ackProfile)

	return nil
}

// EnsureTransport tries to establish transport for a call if relay data is available.
func (cm *CallManager) EnsureTransport(ctx context.Context, callID string) error {
	baseAttemptID, baseSource := callTransportAttemptTraceFromContext(ctx)
	if baseSource == "" {
		baseSource = "unknown"
	}
	for {
		startedAt := time.Now()

		var (
			info             *types.CallInfo
			ok               bool
			attemptID        string
			source           string
			inFlightBefore   int
			inFlightNow      int
			prevAttemptID    string
			transport        CallTransport
			transportState   types.TransportState
			relayDataPresent bool
			preemptCancel    context.CancelFunc
			preemptAge       time.Duration
			preemptAttemptID string
			preemptReason    string
		)

		cm.mu.Lock()
		info, ok = cm.calls[callID]
		if !ok {
			cm.mu.Unlock()
			return fmt.Errorf("call %s not found", callID)
		}
		if info.State == types.CallStateEnded {
			cm.mu.Unlock()
			return nil
		}
		if info.RelayData == nil {
			cm.mu.Unlock()
			return nil
		}
		if info.TransportState == types.TransportStateConnected {
			cm.mu.Unlock()
			return nil
		}
		if info.TransportConnectInFly > 0 {
			inFlightBefore = info.TransportConnectInFly
			prevAttemptID = info.TransportLastAttemptID
			info.TransportRetryQueued = true
			info.TransportRetryQueuedSource = baseSource
			info.TransportRetryQueuedAt = time.Now()
			if baseSource == "remote_accept" {
				if runtime, exists := cm.transportAttempts[callID]; exists && runtime.cancel != nil {
					if runtime.source != "remote_accept" {
						preemptCancel = runtime.cancel
						preemptAttemptID = runtime.attemptID
						preemptReason = "source_mismatch"
					} else if !info.TransportLastAttemptAt.IsZero() {
						preemptAge = time.Since(info.TransportLastAttemptAt)
						if preemptAge >= remoteAcceptPreemptAfter {
							preemptCancel = runtime.cancel
							preemptAttemptID = runtime.attemptID
							preemptReason = "stale_remote_accept"
						}
					}
				}
			}
			cm.mu.Unlock()
			if preemptCancel != nil {
				if cm.cli != nil && cm.cli.Log != nil {
					cm.cli.Log.Warnf(
						"EnsureTransport preempting in-flight attempt call=%s source=%s active_attempt=%s reason=%s age=%s queued_retry=true",
						callID,
						baseSource,
						preemptAttemptID,
						preemptReason,
						preemptAge,
					)
				}
				preemptCancel()
				return nil
			}
			if cm.cli != nil && cm.cli.Log != nil {
				cm.cli.Log.Warnf(
					"EnsureTransport coalesced call=%s source=%s in_flight=%d active_attempt=%s queued_retry=true",
					callID,
					baseSource,
					inFlightBefore,
					prevAttemptID,
				)
			}
			return nil
		}

		info.TransportAttemptSeq++
		prevAttemptID = info.TransportLastAttemptID
		source = baseSource
		if source == "" {
			source = "unknown"
		}
		attemptID = baseAttemptID
		if attemptID == "" {
			attemptID = fmt.Sprintf("%s-%d", shortCallID(callID), info.TransportAttemptSeq)
		}
		info.TransportLastAttemptID = attemptID
		info.TransportLastAttemptSource = source
		info.TransportLastAttemptAt = startedAt
		info.TransportLastAttemptError = ""
		inFlightBefore = info.TransportConnectInFly
		info.TransportState = types.TransportStateConnecting
		info.TransportConnectInFly = 1
		inFlightNow = info.TransportConnectInFly
		transportState = info.TransportState
		relayDataPresent = info.RelayData != nil
		transport = cm.transport
		attemptCtx := withCallTransportAttemptTrace(ctx, attemptID, source)
		attemptCtx, attemptCancel := context.WithCancel(attemptCtx)
		cm.transportAttempts[callID] = transportAttemptRuntime{
			attemptID: attemptID,
			cancel:    attemptCancel,
			source:    source,
			startedAt: startedAt,
		}
		cm.mu.Unlock()

		if cm.cli != nil && cm.cli.Log != nil {
			cm.cli.Log.Debugf(
				"EnsureTransport start call=%s attempt=%s source=%s in_flight_before=%d in_flight_now=%d state=%v",
				callID,
				attemptID,
				source,
				inFlightBefore,
				inFlightNow,
				transportState,
			)
			if inFlightBefore > 0 {
				cm.cli.Log.Warnf(
					"EnsureTransport concurrent attempt detected call=%s attempt=%s source=%s in_flight_before=%d last_attempt=%s",
					callID,
					attemptID,
					source,
					inFlightBefore,
					prevAttemptID,
				)
			}
		}

		err := transport.Connect(attemptCtx, info)
		duration := time.Since(startedAt)
		attemptCancel()

		cm.mu.Lock()
		info, ok = cm.calls[callID]
		if runtime, exists := cm.transportAttempts[callID]; exists && runtime.attemptID == attemptID {
			delete(cm.transportAttempts, callID)
		}
		if !ok {
			cm.mu.Unlock()
			return fmt.Errorf("call %s not found after transport connect", callID)
		}
		if info.TransportConnectInFly > 0 {
			info.TransportConnectInFly--
		}
		queuedRetry := info.TransportRetryQueued
		queuedSource := info.TransportRetryQueuedSource
		info.TransportRetryQueued = false
		info.TransportRetryQueuedSource = ""
		info.TransportRetryQueuedAt = time.Time{}
		info.TransportLastAttemptAt = time.Now()
		if info.State == types.CallStateEnded {
			if cm.cli != nil && cm.cli.Log != nil {
				cm.cli.Log.Debugf(
					"EnsureTransport finished after call ended call=%s attempt=%s source=%s duration=%s err=%v",
					callID,
					attemptID,
					source,
					duration,
					err,
				)
			}
			cm.mu.Unlock()
			return nil
		}
		if err != nil {
			if errors.Is(err, ErrCallTransportNotConfigured) && isFrontendWSRelayTransportMode() {
				info.TransportLastAttemptError = ""
				if info.TransportState != types.TransportStateConnected {
					info.TransportState = types.TransportStateConnecting
				}
				if cm.cli != nil && cm.cli.Log != nil {
					cm.cli.Log.Debugf(
						"EnsureTransport skipped call=%s attempt=%s source=%s duration=%s reason=app_side_transport_mode",
						callID,
						attemptID,
						source,
						duration,
					)
				}
				cm.mu.Unlock()
				return nil
			}
			info.TransportLastAttemptError = err.Error()
			if info.TransportState == types.TransportStateConnected {
				cm.mu.Unlock()
				return nil
			}
			if queuedRetry {
				if cm.cli != nil && cm.cli.Log != nil {
					cm.cli.Log.Warnf(
						"EnsureTransport retrying queued attempt call=%s previous_attempt=%s previous_source=%s next_source=%s duration=%s err=%v",
						callID,
						attemptID,
						source,
						queuedSource,
						duration,
						err,
					)
				}
				cm.mu.Unlock()
				baseAttemptID = ""
				if queuedSource != "" {
					baseSource = queuedSource
				} else {
					baseSource = "queued_retry"
				}
				continue
			}
			info.TransportState = types.TransportStateFailed
			if cm.cli != nil && cm.cli.Log != nil {
				cm.cli.Log.Warnf(
					"EnsureTransport failed call=%s attempt=%s source=%s duration=%s in_flight_remaining=%d err=%v",
					callID,
					attemptID,
					source,
					duration,
					info.TransportConnectInFly,
					err,
				)
			}
			cm.mu.Unlock()
			return err
		}

		info.TransportLastAttemptError = ""
		info.TransportState = types.TransportStateConnected
		info.ConnectedAt = time.Now()
		if info.State == types.CallStateConnecting {
			info.State = types.CallStateActive
		}
		if cm.cli != nil && cm.cli.Log != nil {
			cm.cli.Log.Debugf(
				"EnsureTransport connected call=%s attempt=%s source=%s duration=%s relay_data=%t in_flight_remaining=%d queued_retry=%t",
				callID,
				attemptID,
				source,
				duration,
				relayDataPresent,
				info.TransportConnectInFly,
				queuedRetry,
			)
		}
		cm.mu.Unlock()
		return nil
	}
}

func isFrontendWSRelayTransportMode() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("CALL_TRANSPORT_MODE")), "frontend_ws_relay")
}

// MarkTransportConnected updates call bookkeeping when upper layers have
// determined transport is established.
func (cm *CallManager) MarkTransportConnected(callID string) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	info, ok := cm.calls[callID]
	if !ok || info.State == types.CallStateEnded {
		return false
	}
	if info.TransportConnectedNotified {
		return false
	}
	if info.TransportState == types.TransportStateConnected {
		if info.State == types.CallStateConnecting {
			info.State = types.CallStateActive
		}
		if info.ConnectedAt.IsZero() {
			info.ConnectedAt = time.Now()
		}
		if runtime, ok := cm.transportAttempts[callID]; ok && runtime.cancel != nil {
			runtime.cancel()
			delete(cm.transportAttempts, callID)
		}
		info.TransportConnectedNotified = true
		return true
	}
	info.TransportState = types.TransportStateConnected
	if info.ConnectedAt.IsZero() {
		info.ConnectedAt = time.Now()
	}
	if info.TransportConnectInFly > 0 {
		info.TransportConnectInFly = 0
		if runtime, ok := cm.transportAttempts[callID]; ok && runtime.cancel != nil {
			runtime.cancel()
			delete(cm.transportAttempts, callID)
		}
	}
	if info.State == types.CallStateConnecting {
		info.State = types.CallStateActive
	}
	info.TransportConnectedNotified = true
	return true
}

// CloseTransport closes the current transport for a call.
func (cm *CallManager) CloseTransport(ctx context.Context, callID string) error {
	cm.mu.RLock()
	info, ok := cm.calls[callID]
	transport := cm.transport
	runtime, hasRuntime := cm.transportAttempts[callID]
	cm.mu.RUnlock()
	if !ok {
		return fmt.Errorf("call %s not found", callID)
	}
	if hasRuntime && runtime.cancel != nil {
		runtime.cancel()
	}
	if err := transport.Close(ctx, info); err != nil {
		return err
	}
	cm.mu.Lock()
	defer cm.mu.Unlock()
	delete(cm.transportAttempts, callID)
	info, ok = cm.calls[callID]
	if !ok {
		return fmt.Errorf("call %s not found after transport close", callID)
	}
	if info.State != types.CallStateEnded {
		info.TransportState = types.TransportStatePendingRelay
	}
	if info.MediaState != types.MediaStateNone {
		info.MediaState = types.MediaStateNone
		info.MediaStoppedAt = time.Now()
	}
	return nil
}

// SendTransportPayload sends raw transport payload for a call through the configured transport.
func (cm *CallManager) SendTransportPayload(ctx context.Context, callID string, payload []byte) error {
	cm.mu.RLock()
	info, ok := cm.calls[callID]
	transport := cm.transport
	cm.mu.RUnlock()
	if !ok {
		return fmt.Errorf("call %s not found", callID)
	}
	return transport.Send(ctx, info, payload)
}

// StartMedia starts the media engine for a call when transport and call state are ready.
// The returned boolean indicates whether media transitioned to active in this call.
func (cm *CallManager) StartMedia(ctx context.Context, callID string) (bool, error) {
	cm.mu.Lock()
	info, ok := cm.calls[callID]
	if !ok {
		cm.mu.Unlock()
		return false, fmt.Errorf("call %s not found", callID)
	}
	if info.State != types.CallStateConnecting && info.State != types.CallStateActive {
		cm.mu.Unlock()
		return false, nil
	}
	if info.TransportState != types.TransportStateConnected {
		cm.mu.Unlock()
		return false, nil
	}
	if info.MediaState == types.MediaStateActive || info.MediaState == types.MediaStateStarting {
		cm.mu.Unlock()
		return false, nil
	}
	key := cm.keys[callID]
	if key == nil {
		info.MediaState = types.MediaStateFailed
		info.MediaLastError = "call encryption key unavailable"
		cm.mu.Unlock()
		return false, fmt.Errorf("call %s encryption key unavailable", callID)
	}
	keys := DeriveCallKeys(key)
	if keys == nil {
		info.MediaState = types.MediaStateFailed
		info.MediaLastError = "failed to derive call media keys"
		cm.mu.Unlock()
		return false, fmt.Errorf("failed to derive media keys for call %s", callID)
	}
	info.MediaState = types.MediaStateStarting
	engine := cm.mediaEngine
	cm.mu.Unlock()

	err := engine.Start(ctx, info, keys)

	cm.mu.Lock()
	defer cm.mu.Unlock()
	info, ok = cm.calls[callID]
	if !ok {
		return false, fmt.Errorf("call %s not found after media start", callID)
	}
	if err != nil {
		info.MediaState = types.MediaStateFailed
		info.MediaLastError = err.Error()
		info.MediaStoppedAt = time.Now()
		return false, err
	}
	info.MediaState = types.MediaStateActive
	info.MediaStartedAt = time.Now()
	info.MediaLastError = ""
	return true, nil
}

// StopMedia stops the media engine for a call.
// The returned boolean indicates whether media transitioned to stopped in this call.
func (cm *CallManager) StopMedia(ctx context.Context, callID string) (bool, error) {
	cm.mu.Lock()
	info, ok := cm.calls[callID]
	if !ok {
		cm.mu.Unlock()
		return false, fmt.Errorf("call %s not found", callID)
	}
	if info.MediaState == types.MediaStateNone || info.MediaState == types.MediaStateStopping {
		cm.mu.Unlock()
		return false, nil
	}
	info.MediaState = types.MediaStateStopping
	engine := cm.mediaEngine
	cm.mu.Unlock()

	err := engine.Stop(ctx, info)

	cm.mu.Lock()
	defer cm.mu.Unlock()
	info, ok = cm.calls[callID]
	if !ok {
		return false, fmt.Errorf("call %s not found after media stop", callID)
	}
	if err != nil {
		info.MediaState = types.MediaStateFailed
		info.MediaLastError = err.Error()
		info.MediaStoppedAt = time.Now()
		return false, err
	}
	info.MediaState = types.MediaStateNone
	info.MediaStoppedAt = time.Now()
	return true, nil
}

// SendMediaPayload sends outgoing media payload through transport and updates media counters.
func (cm *CallManager) SendMediaPayload(ctx context.Context, callID string, payload []byte) error {
	cm.mu.RLock()
	info, ok := cm.calls[callID]
	cm.mu.RUnlock()
	if !ok {
		return fmt.Errorf("call %s not found", callID)
	}
	if info.TransportState != types.TransportStateConnected {
		return fmt.Errorf("call %s transport is not connected", callID)
	}
	if len(payload) == 0 {
		return nil
	}
	if err := cm.SendTransportPayload(ctx, callID, payload); err != nil {
		cm.mu.Lock()
		if callInfo, exists := cm.calls[callID]; exists {
			callInfo.MediaState = types.MediaStateFailed
			callInfo.MediaLastError = err.Error()
		}
		cm.mu.Unlock()
		return err
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()
	if callInfo, exists := cm.calls[callID]; exists {
		callInfo.MediaStats.PacketsSent++
		callInfo.MediaStats.BytesSent += uint64(len(payload))
		callInfo.MediaStats.LastPacketSent = time.Now()
	}
	return nil
}

// SendAudioFrame sends an outgoing audio frame through transport as framed media payload.
func (cm *CallManager) SendAudioFrame(ctx context.Context, callID string, frame []byte) error {
	cm.mu.RLock()
	engine := cm.mediaEngine
	cm.mu.RUnlock()
	if packetizer, ok := engine.(CallMediaFramePacketizer); ok {
		payload, err := packetizer.BuildOutgoingAudioPayload(callID, frame)
		if err == nil {
			return cm.SendMediaPayload(ctx, callID, payload)
		}
		if !isMediaSessionInactiveError(err) {
			return err
		}
	}
	return cm.SendMediaPayload(ctx, callID, BuildFramedMediaPayload(MediaPayloadAudio, frame))
}

// SendVideoFrame sends an outgoing video frame through transport as framed media payload.
func (cm *CallManager) SendVideoFrame(ctx context.Context, callID string, frame []byte) error {
	cm.mu.RLock()
	engine := cm.mediaEngine
	cm.mu.RUnlock()
	if packetizer, ok := engine.(CallMediaFramePacketizer); ok {
		payload, err := packetizer.BuildOutgoingVideoPayload(callID, frame)
		if err == nil {
			return cm.SendMediaPayload(ctx, callID, payload)
		}
		if !isMediaSessionInactiveError(err) {
			return err
		}
	}
	return cm.SendMediaPayload(ctx, callID, BuildFramedMediaPayload(MediaPayloadVideo, frame))
}

func isMediaSessionInactiveError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "media session not active")
}

// StartMediaIOPump starts a best-effort source->transport media pump for the call.
func (cm *CallManager) StartMediaIOPump(callID string, interval time.Duration) error {
	cm.mu.Lock()
	if _, ok := cm.calls[callID]; !ok {
		cm.mu.Unlock()
		return fmt.Errorf("call %s not found", callID)
	}
	if interval <= 0 {
		interval = cm.mediaPumpInterval
		if interval <= 0 {
			interval = 20 * time.Millisecond
		}
	}
	engine := cm.mediaEngine
	if cancel, exists := cm.mediaPumpCancels[callID]; exists {
		cancel()
		delete(cm.mediaPumpCancels, callID)
	}
	rootCtx := context.Background()
	if cm.cli != nil && cm.cli.BackgroundEventCtx != nil {
		rootCtx = cm.cli.BackgroundEventCtx
	}
	pumpCtx, cancel := context.WithCancel(rootCtx)
	cm.mediaPumpCancels[callID] = cancel
	cm.mu.Unlock()

	sourceProvider, ok := engine.(CallMediaFrameSourceProvider)
	if !ok {
		cancel()
		cm.mu.Lock()
		delete(cm.mediaPumpCancels, callID)
		cm.mu.Unlock()
		return fmt.Errorf("media engine does not support source pumping")
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		readTimeout := interval / 2
		if readTimeout <= 0 {
			readTimeout = time.Millisecond
		}
		for {
			select {
			case <-pumpCtx.Done():
				return
			case <-ticker.C:
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					cm.pumpOutgoingAudioFrame(pumpCtx, sourceProvider, callID, readTimeout)
				}()
				go func() {
					defer wg.Done()
					cm.pumpOutgoingVideoFrame(pumpCtx, sourceProvider, callID, readTimeout)
				}()
				wg.Wait()
			}
		}
	}()

	return nil
}

// StopMediaIOPump stops a previously started source->transport media pump.
func (cm *CallManager) StopMediaIOPump(callID string) {
	cm.mu.Lock()
	cancel, ok := cm.mediaPumpCancels[callID]
	if ok {
		delete(cm.mediaPumpCancels, callID)
	}
	cm.mu.Unlock()
	if ok {
		cancel()
	}
}

func (cm *CallManager) pumpOutgoingAudioFrame(ctx context.Context, sourceProvider CallMediaFrameSourceProvider, callID string, timeout time.Duration) {
	readCtx, readCancel := context.WithTimeout(ctx, timeout)
	audioFrame, audioErr := sourceProvider.ReadOutgoingAudioFrame(readCtx, callID)
	readCancel()
	if audioErr == nil && len(audioFrame) > 0 {
		if sendErr := cm.SendAudioFrame(ctx, callID, audioFrame); sendErr != nil && cm.cli != nil {
			cm.cli.Log.Warnf("Failed to send pumped audio frame for %s: %v", callID, sendErr)
		}
		return
	}
	if audioErr != nil && !errors.Is(audioErr, ErrNoAudioSource) && !errors.Is(audioErr, context.DeadlineExceeded) && !errors.Is(audioErr, context.Canceled) && cm.cli != nil {
		cm.cli.Log.Warnf("Failed to read pumped audio frame for %s: %v", callID, audioErr)
	}
}

func (cm *CallManager) pumpOutgoingVideoFrame(ctx context.Context, sourceProvider CallMediaFrameSourceProvider, callID string, timeout time.Duration) {
	readCtx, readCancel := context.WithTimeout(ctx, timeout)
	videoFrame, videoErr := sourceProvider.ReadOutgoingVideoFrame(readCtx, callID)
	readCancel()
	if videoErr == nil && len(videoFrame) > 0 {
		if sendErr := cm.SendVideoFrame(ctx, callID, videoFrame); sendErr != nil && cm.cli != nil {
			cm.cli.Log.Warnf("Failed to send pumped video frame for %s: %v", callID, sendErr)
		}
		return
	}
	if videoErr != nil && !errors.Is(videoErr, ErrNoVideoSource) && !errors.Is(videoErr, context.DeadlineExceeded) && !errors.Is(videoErr, context.Canceled) && cm.cli != nil {
		cm.cli.Log.Warnf("Failed to read pumped video frame for %s: %v", callID, videoErr)
	}
}

// HandleIncomingTransportPayload forwards incoming transport payload to the media engine and tracks counters.
func (cm *CallManager) HandleIncomingTransportPayload(ctx context.Context, callID string, payload []byte) error {
	cm.mu.RLock()
	info, ok := cm.calls[callID]
	engine := cm.mediaEngine
	cm.mu.RUnlock()
	if !ok {
		return fmt.Errorf("call %s not found", callID)
	}
	if len(payload) == 0 {
		return nil
	}

	if err := engine.HandleIncomingPayload(ctx, info, payload); err != nil {
		cm.mu.Lock()
		if callInfo, exists := cm.calls[callID]; exists {
			callInfo.MediaState = types.MediaStateFailed
			callInfo.MediaLastError = err.Error()
		}
		cm.mu.Unlock()
		return err
	}
	if provider, ok := engine.(CallMediaFeedbackProvider); ok {
		for _, control := range provider.DrainOutgoingControl(callID) {
			if len(control) == 0 {
				continue
			}
			if sendErr := cm.SendTransportPayload(ctx, callID, control); sendErr != nil {
				cm.mu.Lock()
				if callInfo, exists := cm.calls[callID]; exists {
					callInfo.MediaState = types.MediaStateFailed
					callInfo.MediaLastError = sendErr.Error()
				}
				cm.mu.Unlock()
				return sendErr
			}
		}
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()
	if callInfo, exists := cm.calls[callID]; exists {
		callInfo.MediaStats.PacketsReceived++
		callInfo.MediaStats.BytesReceived += uint64(len(payload))
		callInfo.MediaStats.LastPacketRecv = time.Now()
	}
	return nil
}

// GetMediaStats returns a snapshot of media counters for a call.
func (cm *CallManager) GetMediaStats(callID string) (types.CallMediaStats, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	info, ok := cm.calls[callID]
	if !ok {
		return types.CallMediaStats{}, false
	}
	return info.MediaStats, true
}

// IncrementRetry increments retry bookkeeping for a call and returns the new count.
func (cm *CallManager) IncrementRetry(callID string) (int, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	info, ok := cm.calls[callID]
	if !ok {
		return 0, fmt.Errorf("call %s not found", callID)
	}
	info.RetryCount++
	return info.RetryCount, nil
}

// ExpireStaleCalls expires ringing calls that passed their configured ring timeout.
func (cm *CallManager) ExpireStaleCalls(now time.Time) []string {
	cm.mu.Lock()
	expired := make([]string, 0)
	for callID, info := range cm.calls {
		if info.State != types.CallStateRinging && info.State != types.CallStateIncomingRinging {
			continue
		}
		if info.RingDeadline.IsZero() || now.Before(info.RingDeadline) {
			continue
		}
		cm.markCallEndedLocked(info, now)
		expired = append(expired, callID)
	}
	cm.mu.Unlock()

	if len(expired) > 0 && cm.cli != nil {
		for _, callID := range expired {
			if cm.cli.Log != nil {
				cm.cli.Log.Warnf("Expiring stale ringing call %s due to ring timeout", callID)
			}
			_ = cm.CloseTransport(context.Background(), callID)
			cm.cli.dispatchEvent(&events.CallWebRTCTransportState{
				CallID: callID,
				State:  WebRTCTransportStateClosed.String(),
				Reason: "ring_timeout",
			})
			cm.cli.dispatchEvent(&events.CallTransportFailed{
				CallID: callID,
				Reason: "ring_timeout",
			})
			cm.cli.dispatchEvent(&events.CallTimeout{CallID: callID})
		}
		cm.mu.Lock()
		cm.trimEndedCallsLocked()
		cm.mu.Unlock()
	}
	return expired
}

func (cm *CallManager) handleTransportIncomingPayload(callID string, payload []byte) {
	if len(payload) == 0 {
		return
	}
	ctx := context.Background()
	if cm.cli != nil && cm.cli.BackgroundEventCtx != nil {
		ctx = cm.cli.BackgroundEventCtx
	}

	if err := cm.HandleIncomingTransportPayload(ctx, callID, payload); err != nil {
		if cm.cli != nil {
			cm.cli.Log.Warnf("Failed to process inbound relay payload for %s: %v", callID, err)
			cm.cli.dispatchEvent(&events.CallMediaFailed{CallID: callID, Reason: err.Error()})
		}
		return
	}
	if cm.cli != nil {
		copied := make([]byte, len(payload))
		copy(copied, payload)
		cm.cli.dispatchEvent(&events.CallTransportPayload{CallID: callID, Payload: copied})
		if stats, ok := cm.GetMediaStats(callID); ok {
			cm.cli.dispatchEvent(&events.CallMediaStats{CallID: callID, Stats: stats})
		}
	}
}

// AcceptCall accepts an incoming call. It builds and sends the accept stanza.
func (cm *CallManager) AcceptCall(ctx context.Context, callID string) error {
	cm.mu.RLock()
	info, ok := cm.calls[callID]
	if !ok {
		cm.mu.RUnlock()
		return fmt.Errorf("call %s not found", callID)
	}
	if info.State != types.CallStateIncomingRinging {
		cm.mu.RUnlock()
		return fmt.Errorf("call %s in wrong state %d for AcceptCall", callID, info.State)
	}
	stanza := cm.cli.BuildAcceptStanza(info)
	cm.mu.RUnlock()
	if err := cm.cli.sendNode(ctx, stanza); err != nil {
		return err
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()
	info, ok = cm.calls[callID]
	if !ok {
		return fmt.Errorf("call %s not found after accept send", callID)
	}
	if info.State == types.CallStateIncomingRinging {
		if info.TransportState == types.TransportStateConnected {
			info.State = types.CallStateActive
			if info.ConnectedAt.IsZero() {
				info.ConnectedAt = time.Now()
			}
		} else {
			info.State = types.CallStateConnecting
		}
		info.AcceptedAt = time.Now()
		info.RingDeadline = time.Time{}
	}
	return nil
}

// RejectCall rejects an incoming call.
func (cm *CallManager) RejectCall(ctx context.Context, callID string) error {
	cm.mu.RLock()
	info, ok := cm.calls[callID]
	if !ok {
		cm.mu.RUnlock()
		return fmt.Errorf("call %s not found", callID)
	}
	stanza := cm.cli.BuildRejectStanza(info)
	cm.mu.RUnlock()
	if err := cm.cli.sendNode(ctx, stanza); err != nil {
		return err
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()
	info, ok = cm.calls[callID]
	if !ok {
		return fmt.Errorf("call %s not found after reject send", callID)
	}
	cm.markCallEndedLocked(info, time.Now())
	cm.trimEndedCallsLocked()
	return nil
}

// EndCall terminates an active call.
func (cm *CallManager) EndCall(ctx context.Context, callID string) error {
	cm.mu.RLock()
	info, ok := cm.calls[callID]
	if !ok {
		cm.mu.RUnlock()
		return fmt.Errorf("call %s not found", callID)
	}
	stanza := cm.cli.BuildTerminateStanza(info)
	cm.mu.RUnlock()
	if err := cm.cli.sendNode(ctx, stanza); err != nil {
		return err
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()
	info, ok = cm.calls[callID]
	if !ok {
		return fmt.Errorf("call %s not found after terminate send", callID)
	}
	cm.markCallEndedLocked(info, time.Now())
	cm.trimEndedCallsLocked()
	return nil
}

// SendPreAccept sends a preaccept stanza (shows ringing to caller).
func (cm *CallManager) SendPreAccept(ctx context.Context, callID string) error {
	cm.mu.RLock()
	info, ok := cm.calls[callID]
	cm.mu.RUnlock()
	if !ok {
		return fmt.Errorf("call %s not found", callID)
	}

	stanza := cm.cli.BuildPreAcceptStanza(info)
	return cm.cli.sendNode(ctx, stanza)
}

// SendRelayLatency sends relay latency measurements for a call.
// Each relay endpoint is sent as a separate stanza, matching WAWeb behavior.
func (cm *CallManager) SendRelayLatency(ctx context.Context, callID string) error {
	cm.mu.RLock()
	info, ok := cm.calls[callID]
	cm.mu.RUnlock()
	if !ok {
		return fmt.Errorf("call %s not found", callID)
	}
	if info.RelayData == nil {
		return nil
	}

	stanzas := cm.cli.BuildRelayLatencyStanzas(info, info.RelayData)
	for _, stanza := range stanzas {
		if err := cm.cli.sendNode(ctx, stanza); err != nil {
			return err
		}
	}
	return nil
}

// SendTransport sends a transport stanza for ICE candidate exchange.
func (cm *CallManager) SendTransport(ctx context.Context, callID string) error {
	cm.mu.RLock()
	info, ok := cm.calls[callID]
	cm.mu.RUnlock()
	if !ok {
		return fmt.Errorf("call %s not found", callID)
	}

	stanza := cm.cli.BuildTransportStanza(info)
	return cm.cli.sendNode(ctx, stanza)
}

// SendMuteState sends a mute state change for a call.
func (cm *CallManager) SendMuteState(ctx context.Context, callID string, muted bool) error {
	cm.mu.RLock()
	info, ok := cm.calls[callID]
	cm.mu.RUnlock()
	if !ok {
		return fmt.Errorf("call %s not found", callID)
	}

	stanza := cm.cli.BuildMuteStanza(info, muted)
	return cm.cli.sendNode(ctx, stanza)
}

// SendEncRekey rotates and sends a new encrypted call key generation.
//
// This is primarily relevant for long-running calls where key rotation may be
// requested by the server path.
func (cm *CallManager) SendEncRekey(ctx context.Context, callID string) (*CallEncryptionKey, error) {
	cm.mu.RLock()
	info, ok := cm.calls[callID]
	current := cm.keys[callID]
	cm.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("call %s not found", callID)
	}
	if info.State == types.CallStateEnded {
		return nil, fmt.Errorf("call %s already ended", callID)
	}
	if current == nil {
		return nil, fmt.Errorf("call %s encryption key unavailable", callID)
	}

	nextKey, err := GenerateCallKey()
	if err != nil {
		return nil, err
	}
	if current.Generation > 0 {
		nextKey.Generation = current.Generation + 1
	}

	ciphertext, encType, _, err := cm.cli.EncryptCallKey(ctx, info.PeerJID, &nextKey)
	if err != nil {
		nextKey.Zeroize()
		return nil, err
	}
	stanza := cm.cli.BuildEncRekeyStanza(info, ciphertext, encType, nextKey.Generation)
	if err = cm.cli.sendNode(ctx, stanza); err != nil {
		nextKey.Zeroize()
		return nil, err
	}

	cm.mu.Lock()
	if existing, exists := cm.keys[callID]; exists && existing != nil && existing != &nextKey {
		existing.Zeroize()
	}
	cm.keys[callID] = &nextKey
	cm.mu.Unlock()
	return &nextKey, nil
}

// HoldCall transitions an active call to OnHold and pauses local media.
func (cm *CallManager) HoldCall(ctx context.Context, callID string) error {
	cm.mu.Lock()
	info, ok := cm.calls[callID]
	if !ok {
		cm.mu.Unlock()
		return fmt.Errorf("call %s not found", callID)
	}
	if info.State != types.CallStateActive {
		cm.mu.Unlock()
		return fmt.Errorf("call %s in wrong state %d for HoldCall", callID, info.State)
	}
	info.State = types.CallStateOnHold
	cm.mu.Unlock()

	cm.StopMediaIOPump(callID)
	if _, err := cm.StopMedia(ctx, callID); err != nil {
		cm.mu.Lock()
		if callInfo, exists := cm.calls[callID]; exists && callInfo.State == types.CallStateOnHold {
			callInfo.State = types.CallStateActive
		}
		cm.mu.Unlock()
		return err
	}
	return nil
}

// ResumeCall transitions a held call back into active media flow.
func (cm *CallManager) ResumeCall(ctx context.Context, callID string) error {
	cm.mu.Lock()
	info, ok := cm.calls[callID]
	if !ok {
		cm.mu.Unlock()
		return fmt.Errorf("call %s not found", callID)
	}
	if info.State != types.CallStateOnHold {
		cm.mu.Unlock()
		return fmt.Errorf("call %s in wrong state %d for ResumeCall", callID, info.State)
	}
	if info.TransportState == types.TransportStateConnected {
		info.State = types.CallStateActive
	} else {
		info.State = types.CallStateConnecting
	}
	cm.mu.Unlock()

	started, err := cm.StartMedia(ctx, callID)
	if err != nil {
		cm.mu.Lock()
		if callInfo, exists := cm.calls[callID]; exists {
			callInfo.State = types.CallStateOnHold
		}
		cm.mu.Unlock()
		return err
	}
	if started {
		if pumpErr := cm.StartMediaIOPump(callID, 0); pumpErr != nil && cm.cli != nil && cm.cli.Log != nil {
			cm.cli.Log.Debugf("Media IO pump not started while resuming call %s: %v", callID, pumpErr)
		}
	}
	return nil
}

// HandleRemoteAccept processes a remote accept of an outgoing call.
//
// The boolean return indicates whether this call transitioned into accepted
// state for the first time (used by higher layers to avoid duplicate accept
// side-effects when multiple devices emit accept).
func (cm *CallManager) HandleRemoteAccept(parsed *ParsedCallStanza) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	info, ok := cm.calls[parsed.CallID]
	if !ok {
		if cm.cli != nil && cm.cli.Log != nil {
			cm.cli.Log.Warnf("Received remote accept for unknown call %s from %s", parsed.CallID, parsed.From)
		}
		return false
	}
	if !info.AcceptedAt.IsZero() {
		return false
	}
	if info.State == types.CallStateInitiating || info.State == types.CallStateRinging || info.State == types.CallStateConnecting {
		if info.TransportState == types.TransportStateConnected {
			info.State = types.CallStateActive
			if info.ConnectedAt.IsZero() {
				info.ConnectedAt = time.Now()
			}
		} else {
			info.State = types.CallStateConnecting
		}
		info.AcceptedAt = time.Now()
		info.RingDeadline = time.Time{}
		return true
	} else if cm.cli != nil && cm.cli.Log != nil {
		cm.cli.Log.Debugf("Ignoring remote accept for call %s in state %d", parsed.CallID, info.State)
	}
	return false
}

// HandleRemotePreAccept updates outgoing call timeout bookkeeping when remote
// devices signal ringing via preaccept.
func (cm *CallManager) HandleRemotePreAccept(parsed *ParsedCallStanza) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	info, ok := cm.calls[parsed.CallID]
	if !ok || info == nil || !info.IsInitiator {
		return
	}
	if info.State == types.CallStateEnded {
		return
	}

	extendBy := cm.outgoingRingWindowLocked(info)
	if extendBy < minOutgoingPreAcceptGrace {
		extendBy = minOutgoingPreAcceptGrace
	}
	nextDeadline := time.Now().Add(extendBy)
	if info.RingDeadline.Before(nextDeadline) {
		info.RingDeadline = nextDeadline
	}
}

func (cm *CallManager) outgoingRingWindowLocked(info *types.CallInfo) time.Duration {
	window := cm.ringTimeout
	if info != nil && info.IsInitiator && window < minOutgoingRingTimeout {
		return minOutgoingRingTimeout
	}
	return window
}

// HandleRemoteReject processes a remote rejection of an outgoing call.
func (cm *CallManager) HandleRemoteReject(parsed *ParsedCallStanza) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	info, ok := cm.calls[parsed.CallID]
	if !ok {
		return
	}
	cm.markCallEndedLocked(info, time.Now())
	cm.trimEndedCallsLocked()
}

// HandleTerminate processes a call termination from the remote party.
func (cm *CallManager) HandleTerminate(parsed *ParsedCallStanza) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	info, ok := cm.calls[parsed.CallID]
	if !ok {
		return
	}
	cm.markCallEndedLocked(info, time.Now())
	cm.trimEndedCallsLocked()
}

// HandleRelayElection stores the elected relay index from the server.
func (cm *CallManager) HandleRelayElection(parsed *ParsedCallStanza) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	info, ok := cm.calls[parsed.CallID]
	if !ok {
		return
	}
	if parsed.RelayElection != nil {
		info.ElectedRelayIndex = &parsed.RelayElection.ElectedRelayIndex
	}
}

// StoreEncryptionKey stores a decrypted call encryption key.
func (cm *CallManager) StoreEncryptionKey(callID string, key *CallEncryptionKey) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if existing, ok := cm.keys[callID]; ok && existing != nil && existing != key {
		existing.Zeroize()
	}
	cm.keys[callID] = key
}

// GetEncryptionKey returns the stored encryption key for a call.
func (cm *CallManager) GetEncryptionKey(callID string) *CallEncryptionKey {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.keys[callID]
}

// GetDerivedKeys returns derived SRTP/media keys for a call.
func (cm *CallManager) GetDerivedKeys(callID string) *DerivedCallKeys {
	cm.mu.RLock()
	key := cm.keys[callID]
	cm.mu.RUnlock()
	if key == nil {
		return nil
	}
	return DeriveCallKeys(key)
}

func (cm *CallManager) markCallEndedLocked(info *types.CallInfo, endedAt time.Time) {
	info.State = types.CallStateEnded
	info.EndedAt = endedAt
	info.RingDeadline = time.Time{}
	info.TransportState = types.TransportStateNone
	info.MediaState = types.MediaStateNone
	if info.MediaStoppedAt.IsZero() {
		info.MediaStoppedAt = endedAt
	}
	// Eagerly remove the offer stanza → call ID mapping so stale entries don't
	// accumulate between calls.
	if info.OfferStanzaID != "" {
		delete(cm.offerStanzaToCallID, info.OfferStanzaID)
	}
}

func (cm *CallManager) cleanupCallLocked(callID string) {
	if info, ok := cm.calls[callID]; ok {
		if info.OfferStanzaID != "" {
			delete(cm.offerStanzaToCallID, info.OfferStanzaID)
		}
	}
	if runtime, ok := cm.transportAttempts[callID]; ok && runtime.cancel != nil {
		runtime.cancel()
	}
	if key, ok := cm.keys[callID]; ok && key != nil {
		key.Zeroize()
	}
	delete(cm.transportAttempts, callID)
	delete(cm.calls, callID)
	delete(cm.keys, callID)
}

func (cm *CallManager) trimEndedCallsLocked() {
	if cm.maxEndedCalls <= 0 {
		return
	}
	type endedCall struct {
		callID  string
		endedAt time.Time
	}
	ended := make([]endedCall, 0)
	for callID, info := range cm.calls {
		if info.State != types.CallStateEnded {
			continue
		}
		ended = append(ended, endedCall{callID: callID, endedAt: info.EndedAt})
	}
	if len(ended) <= cm.maxEndedCalls {
		return
	}
	sort.Slice(ended, func(i, j int) bool {
		return ended[i].endedAt.Before(ended[j].endedAt)
	})
	toDrop := len(ended) - cm.maxEndedCalls
	for i := 0; i < toDrop; i++ {
		cm.cleanupCallLocked(ended[i].callID)
	}
}

// CleanupCall removes a call and its encryption key from the manager.
func (cm *CallManager) CleanupCall(callID string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.cleanupCallLocked(callID)
}
