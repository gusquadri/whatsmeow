// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"strings"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

func (cli *Client) getOwnIDForCallPeer(peer types.JID) types.JID {
	ownID := cli.getOwnID()
	ownLID := cli.getOwnLID()

	peerIsLID := peer.Server == types.HiddenUserServer || peer.Server == types.HostedLIDServer
	if peerIsLID {
		if !ownLID.IsEmpty() {
			if ownLID.Device == 0 && ownID.Device != 0 {
				ownLID.Device = ownID.Device
			}
			return ownLID
		}
		if !ownID.IsEmpty() {
			return ownID
		}
		return types.EmptyJID
	}

	if !ownID.IsEmpty() {
		return ownID
	}
	if !ownLID.IsEmpty() {
		return ownLID
	}
	return types.EmptyJID
}

func (cli *Client) resolveCallKeySenderJID(ctx context.Context, parsed *ParsedCallStanza) types.JID {
	if parsed == nil {
		return types.EmptyJID
	}
	callerPN := parsed.CallerPN
	callCreator := parsed.CallCreator

	// Prefer migrated LID identity when offer provides both caller_pn and LID call-creator.
	if !callerPN.IsEmpty() && (callCreator.Server == types.HiddenUserServer || callCreator.Server == types.HostedLIDServer) {
		cli.migrateSessionStore(ctx, callerPN, callCreator)
		return callCreator
	}

	resolveLIDForPN := func(pn types.JID) types.JID {
		if pn.IsEmpty() || pn.Server != types.DefaultUserServer || cli == nil || cli.Store == nil || cli.Store.LIDs == nil {
			return types.EmptyJID
		}
		lid, err := cli.Store.LIDs.GetLIDForPN(ctx, pn)
		if err != nil {
			if cli.Log != nil {
				cli.Log.Warnf("Failed to resolve LID for call sender %s: %v", pn, err)
			}
			return types.EmptyJID
		}
		if lid.IsEmpty() {
			return types.EmptyJID
		}
		if lid.Device == 0 && pn.Device != 0 {
			lid.Device = pn.Device
		}
		cli.migrateSessionStore(ctx, pn, lid)
		return lid
	}

	if !callerPN.IsEmpty() {
		if lid := resolveLIDForPN(callerPN); !lid.IsEmpty() {
			return lid
		}
		return callerPN
	}

	if !callCreator.IsEmpty() {
		if callCreator.Server == types.DefaultUserServer {
			if lid := resolveLIDForPN(callCreator); !lid.IsEmpty() {
				return lid
			}
		}
		return callCreator
	}

	return parsed.From
}

func (cli *Client) handleCallEvent(ctx context.Context, node *waBinary.Node) {
	var cancelled bool
	defer cli.maybeDeferredAck(ctx, node)(&cancelled)
	if cli.callManager != nil {
		cli.callManager.ExpireStaleCalls(time.Now())
	}

	parsed, err := ParseCallStanza(node)
	if err != nil {
		cli.Log.Warnf("Failed to parse call stanza: %v", err)
		cli.dispatchEvent(&events.UnknownCallEvent{Node: node})
		return
	}

	// Send typed ACK or Receipt (cancels default ack)
	cli.sendCallResponse(ctx, parsed)
	cancelled = true

	// Build basic metadata for backward-compatible events
	ag := node.AttrGetter()
	child := parsed.RawNode
	if child == nil {
		cli.dispatchEvent(&events.UnknownCallEvent{Node: node})
		return
	}
	cag := child.AttrGetter()
	basicMeta := types.BasicCallMeta{
		From:        ag.JID("from"),
		Timestamp:   ag.UnixTime("t"),
		CallCreator: cag.JID("call-creator"),
		CallID:      cag.String("call-id"),
		GroupJID:    cag.OptionalJIDOrEmpty("group-jid"),
	}
	if basicMeta.CallCreator.Server == types.HiddenUserServer {
		basicMeta.CallCreatorAlt = cag.OptionalJIDOrEmpty("caller_pn")
	} else {
		basicMeta.CallCreatorAlt = cag.OptionalJIDOrEmpty("caller_lid")
	}
	remoteMeta := types.CallRemoteMeta{
		RemotePlatform: ag.OptionalString("platform"),
		RemoteVersion:  ag.OptionalString("version"),
	}

	// Route to CallManager and dispatch events
	switch parsed.SignalingType {
	case types.SignalingOffer:
		cli.handleIncomingOffer(ctx, parsed, basicMeta, remoteMeta, node, child)
	case types.SignalingOfferReceipt:
		cli.dispatchEvent(&events.CallOfferReceipt{
			BasicCallMeta: basicMeta,
			Data:          child,
		})
	case types.SignalingOfferNotice:
		cli.dispatchEvent(&events.CallOfferNotice{
			BasicCallMeta: basicMeta,
			Media:         cag.String("media"),
			Type:          cag.String("type"),
			Data:          child,
		})
	case types.SignalingAccept:
		shouldDispatchAccept := true
		acceptedTransition := false
		transportConnectedDispatched := false
		if cli.callManager != nil {
			acceptedTransition = cli.callManager.HandleRemoteAccept(parsed)
			callState, transportState, callExists := cli.callManager.GetCallStateSnapshot(parsed.CallID)
			// Ignore late accepts for already ended/unknown calls to avoid emitting
			// misleading transport-connected events for stale call IDs.
			if !callExists || callState == types.CallStateEnded {
				shouldDispatchAccept = false
				if cli.Log != nil {
					cli.Log.Debugf("Ignoring accept for stale call %s (state=%v)", parsed.CallID, callState)
				}
			} else {
				// Accept can arrive before earlier relay/offer-ack driven transport setup
				// completes. Re-run transport signaling/ensure here to avoid lingering in
				// connecting state due timing races.
				if err := cli.callManager.SendTransport(ctx, parsed.CallID); err != nil && cli.Log != nil {
					cli.Log.Debugf("Failed to send transport signaling after accept for %s: %v", parsed.CallID, err)
				}
				cli.ensureCallTransportAsync(ctx, parsed.CallID, "remote_accept")
				if transportState == types.TransportStateConnected {
					cli.handleTransportConnected(ctx, parsed.CallID)
					transportConnectedDispatched = true
				}
				cli.maybeStartCallMedia(ctx, parsed.CallID)
				if cli.Log != nil {
					cli.Log.Debugf(
						"Processed remote accept for %s: accepted_transition=%t transport_connected_dispatched=%t state=%v transport=%v",
						parsed.CallID,
						acceptedTransition,
						transportConnectedDispatched,
						callState,
						transportState,
					)
				}
			}
		}
		if shouldDispatchAccept {
			cli.dispatchEvent(&events.CallAccept{
				BasicCallMeta:  basicMeta,
				CallRemoteMeta: remoteMeta,
				Data:           child,
			})
		}
	case types.SignalingPreAccept:
		if cli.callManager != nil {
			cli.callManager.HandleRemotePreAccept(parsed)
		}
		cli.dispatchEvent(&events.CallPreAccept{
			BasicCallMeta:  basicMeta,
			CallRemoteMeta: remoteMeta,
			Data:           child,
		})
	case types.SignalingAcceptReceipt:
		cli.dispatchEvent(&events.CallAcceptReceipt{
			BasicCallMeta: basicMeta,
			Data:          child,
		})
	case types.SignalingTransport:
		if cli.callManager != nil {
			cli.maybeStartCallMedia(ctx, parsed.CallID)
			payload := parsed.Payload
			if parsed.TransportData != nil && len(parsed.TransportData.RawData) > 0 {
				payload = parsed.TransportData.RawData
			}
			if len(payload) == 0 {
				if rawPayload, ok := decodeRawBytes(child.Content); ok {
					payload = rawPayload
				}
			}
			if len(payload) > 0 {
				if err := cli.callManager.HandleIncomingTransportPayload(ctx, parsed.CallID, payload); err != nil {
					cli.Log.Warnf("Failed to process incoming transport payload for %s: %v", parsed.CallID, err)
					cli.dispatchEvent(&events.CallMediaFailed{CallID: parsed.CallID, Reason: err.Error()})
				} else {
					cli.dispatchEvent(&events.CallTransportPayload{
						CallID:  parsed.CallID,
						Payload: append([]byte(nil), payload...),
					})
					cli.dispatchCallMediaStats(parsed.CallID)
				}
			}
		}
		cli.dispatchEvent(&events.CallTransport{
			BasicCallMeta:  basicMeta,
			CallRemoteMeta: remoteMeta,
			Data:           child,
			TransportData:  parsed.TransportData,
		})
	case types.SignalingRelayLatency:
		cli.dispatchEvent(&events.CallRelayLatency{
			BasicCallMeta: basicMeta,
			Data:          child,
		})
	case types.SignalingRelayElection:
		if cli.callManager != nil {
			cli.callManager.HandleRelayElection(parsed)
			if err := cli.callManager.SendTransport(ctx, parsed.CallID); err != nil {
				if cli.Log != nil {
					cli.Log.Warnf("Failed to send transport signaling after relay election for %s: %v", parsed.CallID, err)
				}
			}
			ensureCtx := withCallTransportAttemptTrace(ctx, "", "relay_election")
			if err := cli.callManager.EnsureTransport(ensureCtx, parsed.CallID); err != nil {
				if cli.Log != nil {
					cli.Log.Warnf("Failed to ensure call transport after relay election for %s: %v", parsed.CallID, err)
				}
				cli.dispatchEvent(&events.CallTransportFailed{CallID: parsed.CallID, Reason: err.Error()})
			} else if callInfo := cli.callManager.GetCall(parsed.CallID); callInfo != nil && callInfo.TransportState == types.TransportStateConnected {
				cli.handleTransportConnected(ctx, parsed.CallID)
			}
		}
		cli.dispatchEvent(&events.CallRelayElection{
			BasicCallMeta: basicMeta,
			Data:          child,
			ElectedRelay:  parsed.RelayElection,
		})
	case types.SignalingTerminate:
		if cli.callManager != nil {
			cli.stopCallMedia(ctx, parsed.CallID, "terminate")
			cli.callManager.HandleTerminate(parsed)
			if err := cli.callManager.CloseTransport(ctx, parsed.CallID); err != nil {
				cli.Log.Warnf("Failed to close call transport after terminate for %s: %v", parsed.CallID, err)
			}
		}
		cli.dispatchEvent(&events.CallTerminate{
			BasicCallMeta: basicMeta,
			Reason:        cag.OptionalString("reason"),
			Data:          child,
		})
	case types.SignalingReject:
		if cli.callManager != nil {
			cli.stopCallMedia(ctx, parsed.CallID, "reject")
			cli.callManager.HandleRemoteReject(parsed)
			if err := cli.callManager.CloseTransport(ctx, parsed.CallID); err != nil {
				cli.Log.Warnf("Failed to close call transport after reject for %s: %v", parsed.CallID, err)
			}
		}
		cli.dispatchEvent(&events.CallReject{
			BasicCallMeta: basicMeta,
			Data:          child,
		})
	case types.SignalingEncRekey:
		cli.dispatchEvent(&events.CallEncRekey{
			BasicCallMeta: basicMeta,
			Data:          child,
			EncData:       parsed.OfferEncData,
			Rekey:         parsed.EncRekeyData,
		})
	case types.SignalingInterruption:
		cli.dispatchEvent(&events.CallInterruption{
			BasicCallMeta: basicMeta,
			Data:          child,
		})
	case types.SignalingVideoState:
		cli.dispatchEvent(&events.CallVideoState{
			BasicCallMeta: basicMeta,
			Data:          child,
		})
	case types.SignalingVideoStateAck:
		cli.dispatchEvent(&events.CallVideoStateAck{
			BasicCallMeta: basicMeta,
			Data:          child,
		})
	case types.SignalingNotify:
		cli.dispatchEvent(&events.CallNotify{
			BasicCallMeta: basicMeta,
			Data:          child,
		})
	case types.SignalingGroupInfo:
		cli.dispatchEvent(&events.CallGroupInfo{
			BasicCallMeta: basicMeta,
			Data:          child,
		})
	case types.SignalingPeerState:
		cli.dispatchEvent(&events.CallPeerState{
			BasicCallMeta: basicMeta,
			Data:          child,
		})
	case types.SignalingFlowControl:
		cli.dispatchEvent(&events.CallFlowControl{
			BasicCallMeta: basicMeta,
			Data:          child,
		})
	case types.SignalingWebClient:
		cli.dispatchEvent(&events.CallWebClient{
			BasicCallMeta: basicMeta,
			Data:          child,
		})
	case types.SignalingAcceptAck:
		cli.dispatchEvent(&events.CallAcceptAck{
			BasicCallMeta: basicMeta,
			Data:          child,
		})
	case types.SignalingGroupUpdate:
		cli.dispatchEvent(&events.CallGroupUpdate{
			BasicCallMeta: basicMeta,
			Data:          child,
		})
	case types.SignalingMuteV2, types.SignalingMute:
		cli.dispatchEvent(&events.CallMuteState{
			BasicCallMeta: basicMeta,
			Data:          child,
		})
	default:
		cli.dispatchEvent(&events.UnknownCallEvent{Node: node})
	}
}

func (cli *Client) handleIncomingOffer(ctx context.Context, parsed *ParsedCallStanza, basicMeta types.BasicCallMeta, remoteMeta types.CallRemoteMeta, node *waBinary.Node, child *waBinary.Node) {
	if parsed.IsOffline {
		cli.Log.Debugf("Skipping offline call %s (stale delivery)", parsed.CallID)
	} else if cli.callManager != nil {
		// Register the call in the manager
		_, err := cli.callManager.RegisterIncomingCall(parsed)
		if err != nil {
			cli.Log.Warnf("Failed to register incoming call %s: %v", parsed.CallID, err)
		}

		// Decrypt call key if present
		if parsed.OfferEncData != nil {
			senderJID := cli.resolveCallKeySenderJID(ctx, parsed)
			key, err := cli.DecryptCallKey(ctx, senderJID, parsed.OfferEncData.Ciphertext, parsed.OfferEncData.EncType)
			if err != nil {
				cli.Log.Warnf("Failed to decrypt call key for %s: %v", parsed.CallID, err)
			} else {
				cli.callManager.StoreEncryptionKey(parsed.CallID, key)
			}
		}

		// Auto-send preaccept (shows ringing to caller)
		if err := cli.callManager.SendPreAccept(ctx, parsed.CallID); err != nil {
			cli.Log.Warnf("Failed to send preaccept for %s: %v", parsed.CallID, err)
		}

		// Auto-send relay latency measurements
		if err := cli.callManager.SendRelayLatency(ctx, parsed.CallID); err != nil {
			cli.Log.Warnf("Failed to send relay latency for %s: %v", parsed.CallID, err)
		}
		// Mirror milestone contract and WAWeb signaling behavior by sending an
		// early transport stanza after offer/relay processing.
		if err := cli.callManager.SendTransport(ctx, parsed.CallID); err != nil {
			cli.Log.Warnf("Failed to send transport signaling for %s: %v", parsed.CallID, err)
		}

		cli.ensureCallTransportAsync(ctx, parsed.CallID, "incoming_offer")
	}

	var offerEventNode *waBinary.Node
	if node != nil && node.Tag == "call" {
		rootCopy := *node
		offerEventNode = &rootCopy
	} else {
		offerEventNode = child
	}

	cli.dispatchEvent(&events.CallOffer{
		BasicCallMeta:      basicMeta,
		CallRemoteMeta:     remoteMeta,
		StanzaID:           parsed.StanzaID,
		IsVideo:            parsed.IsVideo,
		MediaParams:        parsed.MediaParams,
		RelayData:          parsed.RelayData,
		Joinable:           parsed.Joinable,
		CallerCountryCode:  parsed.CallerCountryCode,
		Capability:         append([]byte(nil), parsed.Capability...),
		Metadata:           parsed.Metadata,
		RTE:                append([]byte(nil), parsed.RTE...),
		HasUploadFieldStat: parsed.HasUploadFieldStat,
		VoIPSettings:       parsed.VoIPSettings,
		Data:               offerEventNode,
	})
}

func (cli *Client) sendCallResponse(ctx context.Context, parsed *ParsedCallStanza) {
	ownID := cli.getOwnIDForCallPeer(parsed.From)
	if ownID.IsEmpty() {
		return
	}

	responseType := parsed.SignalingType.GetResponseType()
	switch responseType {
	case types.ResponseTypeReceipt:
		receipt := BuildCallReceipt(parsed.StanzaID, parsed.From, ownID, parsed.SignalingType, parsed.CallID, parsed.CallCreator)
		if err := cli.sendNode(ctx, receipt); err != nil {
			cli.Log.Warnf("Failed to send call receipt: %v", err)
		}
	case types.ResponseTypeAck:
		ack := BuildCallAck(parsed.StanzaID, parsed.From, parsed.SignalingType, parsed.CallID, parsed.CallCreator)
		if err := cli.sendNode(ctx, ack); err != nil {
			cli.Log.Warnf("Failed to send call ack: %v", err)
		}
	}
}

// RejectCall rejects an incoming call. This is the legacy API — for new code, use GetCallManager().RejectCall().
func (cli *Client) RejectCall(ctx context.Context, callFrom types.JID, callID string) error {
	if cli.getOwnIDForCallPeer(callFrom).IsEmpty() {
		return ErrNotLoggedIn
	}
	return cli.sendNode(ctx, waBinary.Node{
		Tag:   "call",
		Attrs: waBinary.Attrs{"id": cli.GenerateMessageID(), "to": callFrom},
		Content: []waBinary.Node{{
			Tag:     "reject",
			Attrs:   waBinary.Attrs{"call-id": callID, "call-creator": callFrom, "count": "0"},
			Content: nil,
		}},
	})
}

// StartCall initiates a new outgoing call to the specified JID.
// Returns the call ID on success.
func (cli *Client) StartCall(ctx context.Context, peerJID types.JID, options types.CallOptions) (string, error) {
	if cli.callManager == nil {
		return "", ErrNotLoggedIn
	}

	resolvedPeerJID := cli.callManager.resolveCallSignalingPeerJID(ctx, peerJID)
	cli.cleanupConflictingOutgoingCalls(ctx, resolvedPeerJID)

	info, key, err := cli.callManager.StartCall(ctx, resolvedPeerJID, options)
	if err != nil {
		return "", err
	}

	cli.runCallStartPreflight(ctx, info.PeerJID)
	if info.OfferExtensions == nil {
		info.OfferExtensions = &types.CallOfferExtensions{}
	}
	if len(info.OfferExtensions.Privacy) == 0 {
		if privacy := cli.loadCallOfferPrivacyToken(ctx, info.PeerJID); len(privacy) > 0 {
			info.OfferExtensions.Privacy = privacy
		} else if cli.Log != nil {
			cli.Log.Debugf("No privacy token cached for call peer %s; offer will be sent without <privacy>", info.PeerJID)
		}
	}

	// Encrypt call key fanout for recipient devices.
	encTargets, includeIdentity, err := cli.EncryptCallKeyForOffer(ctx, info.PeerJID, key)
	if err != nil {
		cli.callManager.CleanupCall(info.CallID)
		return "", err
	}
	// WAWeb call offers include device identity payload consistently; this avoids
	// second-attempt regressions where all fanout entries are "msg" sessions.
	if cli.MessengerConfig == nil {
		includeIdentity = true
	}

	// Build and send offer stanza
	offer := cli.BuildOfferStanzaWithDestinations(info, encTargets, includeIdentity)
	cli.logOutgoingCallOfferShape(info, offer)
	if offerID := callAttrString(offer.Attrs["id"]); offerID != "" {
		if err := cli.callManager.TrackOutgoingOffer(info.CallID, offerID); err != nil {
			cli.callManager.CleanupCall(info.CallID)
			return "", err
		}
	}
	if err := cli.sendNode(ctx, offer); err != nil {
		cli.callManager.CleanupCall(info.CallID)
		return "", err
	}
	// Emit a synthetic CallOffer event for outgoing calls so external consumers
	// can mirror the exact offer signaling stanza (e.g. WAWeb-compatible local
	// VoIP engines) before ACK/message signaling arrives.
	offerNode := offer.GetChildByTag("offer")
	if offerNode.Tag != "" {
		offerRootCopy := offer
		remotePlatform, _ := offer.Attrs["platform"].(string)
		remoteVersion, _ := offer.Attrs["version"].(string)
		cli.dispatchEvent(&events.CallOffer{
			BasicCallMeta: types.BasicCallMeta{
				From:        info.PeerJID,
				Timestamp:   time.Now(),
				CallCreator: info.PeerJID,
				CallID:      info.CallID,
				GroupJID:    info.GroupJID,
			},
			CallRemoteMeta: types.CallRemoteMeta{
				RemotePlatform: remotePlatform,
				RemoteVersion:  remoteVersion,
			},
			IsVideo:   info.IsVideo,
			RelayData: info.RelayData,
			Data:      &offerRootCopy,
		})
	}

	if err := cli.callManager.MarkOfferSent(info.CallID); err != nil {
		return "", err
	}

	return info.CallID, nil
}

func (cli *Client) cleanupConflictingOutgoingCalls(ctx context.Context, peerJID types.JID) {
	if cli == nil || cli.callManager == nil {
		return
	}
	conflicts := cli.callManager.getNonEndedCallIDsByPeer(peerJID)
	for _, callID := range conflicts {
		if cli.Log != nil {
			cli.Log.Warnf("Cleaning up existing non-ended call %s before starting a new call to %s", callID, peerJID)
		}
		cli.stopCallMedia(ctx, callID, "superseded_by_new_call")
		if err := cli.callManager.EndCall(ctx, callID); err != nil && cli.Log != nil {
			cli.Log.Debugf("Failed to send terminate while cleaning conflicting call %s: %v", callID, err)
		}
		if err := cli.callManager.CloseTransport(ctx, callID); err != nil && cli.Log != nil {
			cli.Log.Debugf("Failed to close transport while cleaning conflicting call %s: %v", callID, err)
		}
		cli.callManager.CleanupCall(callID)
	}
}

func (cli *Client) logOutgoingCallOfferShape(info *types.CallInfo, stanza waBinary.Node) {
	if cli == nil || cli.Log == nil || info == nil {
		return
	}
	offerNode := stanza.GetChildByTag("offer")
	if offerNode.Tag == "" {
		return
	}
	destinations := 0
	if destination := offerNode.GetChildByTag("destination"); destination.Tag != "" {
		destinations = len(destination.GetChildrenByTag("to"))
	}
	cli.Log.Debugf(
		"Outgoing call offer %s to %s: destinations=%d device_identity=%t privacy=%t relay=%t voip_settings=%t metadata=%t rte=%t",
		info.CallID,
		info.PeerJID,
		destinations,
		offerNode.GetChildByTag("device-identity").Tag != "",
		offerNode.GetChildByTag("privacy").Tag != "",
		offerNode.GetChildByTag("relay").Tag != "",
		offerNode.GetChildByTag("voip_settings").Tag != "",
		offerNode.GetChildByTag("metadata").Tag != "",
		offerNode.GetChildByTag("rte").Tag != "",
	)
}

func callAttrString(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	default:
		return ""
	}
}

func (cli *Client) loadCallOfferPrivacyToken(ctx context.Context, peer types.JID) []byte {
	if cli == nil || cli.Store == nil || cli.Store.PrivacyTokens == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	readToken := func(user types.JID) []byte {
		if user.IsEmpty() {
			return nil
		}
		token, err := cli.Store.PrivacyTokens.GetPrivacyToken(ctx, user.ToNonAD())
		if err != nil || token == nil || len(token.Token) == 0 {
			return nil
		}
		return append([]byte(nil), token.Token...)
	}

	if token := readToken(peer); len(token) > 0 {
		return token
	}
	if peer.Server == types.HiddenUserServer || peer.Server == types.HostedLIDServer {
		if cli.Store.LIDs != nil {
			pn, err := cli.Store.LIDs.GetPNForLID(ctx, peer.ToNonAD())
			if err == nil {
				if token := readToken(pn); len(token) > 0 {
					return token
				}
			}
		}
	}
	return nil
}

func (cli *Client) defaultCallOfferCountryCode() string {
	if cli == nil {
		return ""
	}

	readCountry := func(payloadGetter func() string) string {
		if payloadGetter == nil {
			return ""
		}
		country := strings.ToUpper(strings.TrimSpace(payloadGetter()))
		return country
	}

	if country := readCountry(func() string {
		if cli.GetClientPayload == nil {
			return ""
		}
		payload := cli.GetClientPayload()
		if payload == nil || payload.GetUserAgent() == nil {
			return ""
		}
		return payload.GetUserAgent().GetLocaleCountryIso31661Alpha2()
	}); country != "" {
		return country
	}

	if cli.Store != nil {
		if country := readCountry(func() string {
			payload := cli.Store.GetClientPayload()
			if payload == nil || payload.GetUserAgent() == nil {
				return ""
			}
			return payload.GetUserAgent().GetLocaleCountryIso31661Alpha2()
		}); country != "" {
			return country
		}
	}

	return ""
}

// AcceptCall accepts an incoming call by its call ID.
func (cli *Client) AcceptCall(ctx context.Context, callID string) error {
	if cli.callManager == nil {
		return ErrNotLoggedIn
	}
	if err := cli.callManager.AcceptCall(ctx, callID); err != nil {
		return err
	}
	cli.maybeStartCallMedia(ctx, callID)
	return nil
}

// EndCall terminates an active call by its call ID.
func (cli *Client) EndCall(ctx context.Context, callID string) error {
	if cli.callManager == nil {
		return ErrNotLoggedIn
	}
	cli.stopCallMedia(ctx, callID, "local_end")
	if err := cli.callManager.EndCall(ctx, callID); err != nil {
		return err
	}
	if err := cli.callManager.CloseTransport(ctx, callID); err != nil {
		cli.Log.Warnf("Failed to close call transport for %s: %v", callID, err)
	}
	return nil
}

// SendEncRekey rotates and sends a new encrypted call key generation for an active call.
func (cli *Client) SendEncRekey(ctx context.Context, callID string) (*CallEncryptionKey, error) {
	if cli.callManager == nil {
		return nil, ErrNotLoggedIn
	}
	return cli.callManager.SendEncRekey(ctx, callID)
}

// HoldCall marks an active call as on-hold and pauses local media flow.
func (cli *Client) HoldCall(ctx context.Context, callID string) error {
	if cli.callManager == nil {
		return ErrNotLoggedIn
	}
	return cli.callManager.HoldCall(ctx, callID)
}

// ResumeCall resumes a previously held call and restarts local media flow.
func (cli *Client) ResumeCall(ctx context.Context, callID string) error {
	if cli.callManager == nil {
		return ErrNotLoggedIn
	}
	return cli.callManager.ResumeCall(ctx, callID)
}

// GetCallManager returns the call manager for advanced call control.
func (cli *Client) GetCallManager() *CallManager {
	return cli.callManager
}

// SetCallTransport configures the Phase 2 call transport implementation.
func (cli *Client) SetCallTransport(transport CallTransport) error {
	if cli.callManager == nil {
		return ErrNotLoggedIn
	}
	if webrtcTransport, ok := transport.(*WebRTCRelayCallTransport); ok {
		webrtcTransport.SetStateHandler(func(callID string, state WebRTCTransportState, reason error) {
			stateEvt := &events.CallWebRTCTransportState{
				CallID: callID,
				State:  state.String(),
			}
			if reason != nil {
				stateEvt.Reason = reason.Error()
			}
			cli.dispatchEvent(stateEvt)
		})
	}
	cli.callManager.SetTransport(transport)
	return nil
}

// SetCallRelayAllocator configures an optional pre-offer relay allocator.
func (cli *Client) SetCallRelayAllocator(allocator CallRelayAllocator) error {
	if cli.callManager == nil {
		return ErrNotLoggedIn
	}
	cli.callManager.SetRelayAllocator(allocator)
	return nil
}

// SetCallOfferProfileProvider configures an optional pre-offer profile provider.
func (cli *Client) SetCallOfferProfileProvider(provider CallOfferProfileProvider) error {
	if cli.callManager == nil {
		return ErrNotLoggedIn
	}
	cli.callManager.SetOfferProfileProvider(provider)
	return nil
}

// SetCallMediaEngine configures the Phase 3 call media engine implementation.
func (cli *Client) SetCallMediaEngine(engine CallMediaEngine) error {
	if cli.callManager == nil {
		return ErrNotLoggedIn
	}
	cli.callManager.SetMediaEngine(engine)
	return nil
}

// SetCallMediaIO configures media IO adapters on engines that support IO configuration.
func (cli *Client) SetCallMediaIO(io CallMediaIO) error {
	if cli.callManager == nil {
		return ErrNotLoggedIn
	}
	cli.callManager.SetMediaIO(io)
	return nil
}

// StartCallMediaIOPump starts media source pumping for an active call.
func (cli *Client) StartCallMediaIOPump(callID string, interval time.Duration) error {
	if cli.callManager == nil {
		return ErrNotLoggedIn
	}
	return cli.callManager.StartMediaIOPump(callID, interval)
}

// StopCallMediaIOPump stops media source pumping for a call.
func (cli *Client) StopCallMediaIOPump(callID string) {
	if cli.callManager == nil {
		return
	}
	cli.callManager.StopMediaIOPump(callID)
}

func (cli *Client) handleTransportConnected(ctx context.Context, callID string) {
	connectedTransition := true
	if cli.callManager != nil {
		connectedTransition = cli.callManager.MarkTransportConnected(callID)
	}
	if connectedTransition {
		cli.dispatchEvent(&events.CallTransportConnected{CallID: callID})
		// Mirror connected as a transport state event so downstream consumers that
		// track only state transitions (call.transport.state) still progress.
		cli.dispatchEvent(&events.CallWebRTCTransportState{
			CallID: callID,
			State:  WebRTCTransportStateConnected.String(),
		})
	}
	cli.maybeStartCallMedia(ctx, callID)
}

func (cli *Client) maybeStartCallMedia(ctx context.Context, callID string) {
	if cli.callManager == nil {
		return
	}
	started, err := cli.callManager.StartMedia(ctx, callID)
	if err != nil {
		cli.Log.Warnf("Failed to start media for %s: %v", callID, err)
		cli.dispatchEvent(&events.CallMediaFailed{CallID: callID, Reason: err.Error()})
		return
	}
	if started {
		cli.dispatchEvent(&events.CallMediaStarted{CallID: callID})
		cli.dispatchCallMediaStats(callID)
		if err = cli.callManager.StartMediaIOPump(callID, 0); err != nil {
			cli.Log.Debugf("Media IO pump not started for %s: %v", callID, err)
		}
	}
}

func (cli *Client) ensureCallTransportAsync(ctx context.Context, callID, source string) {
	if cli == nil || cli.callManager == nil {
		return
	}
	ensureCtx := ctx
	if ensureCtx == nil {
		ensureCtx = context.Background()
	}
	go func() {
		attemptCtx := withCallTransportAttemptTrace(ensureCtx, "", source)
		if err := cli.callManager.EnsureTransport(attemptCtx, callID); err != nil {
			if cli.Log != nil {
				cli.Log.Warnf("Failed to ensure call transport (%s) for %s: %v", source, callID, err)
			}
			cli.dispatchEvent(&events.CallTransportFailed{CallID: callID, Reason: err.Error()})
			return
		}
		if callInfo := cli.callManager.GetCall(callID); callInfo != nil && callInfo.TransportState == types.TransportStateConnected {
			cli.handleTransportConnected(ensureCtx, callID)
		}
	}()
}

func (cli *Client) stopCallMedia(ctx context.Context, callID, reason string) {
	if cli.callManager == nil {
		return
	}
	cli.callManager.StopMediaIOPump(callID)
	stopped, err := cli.callManager.StopMedia(ctx, callID)
	if err != nil {
		cli.Log.Warnf("Failed to stop media for %s: %v", callID, err)
		cli.dispatchEvent(&events.CallMediaFailed{CallID: callID, Reason: err.Error()})
		return
	}
	if stopped {
		cli.dispatchEvent(&events.CallMediaStopped{CallID: callID, Reason: reason})
		cli.dispatchCallMediaStats(callID)
	}
}

func (cli *Client) dispatchCallMediaStats(callID string) {
	if cli.callManager == nil {
		return
	}
	stats, ok := cli.callManager.GetMediaStats(callID)
	if !ok {
		return
	}
	cli.dispatchEvent(&events.CallMediaStats{
		CallID: callID,
		Stats:  stats,
	})
}

func (cli *Client) handleAckNode(ctx context.Context, node *waBinary.Node) {
	ag := node.AttrGetter()
	if ag.OptionalString("class") != "call" {
		return
	}
	cli.handleCallAckEvent(ctx, node)
}

func (cli *Client) handleCallAckEvent(ctx context.Context, node *waBinary.Node) {
	ag := node.AttrGetter()
	ackType := types.SignalingTypeFromTag(ag.OptionalString("type"))
	if ackType == types.SignalingOfferNack {
		if cli.Log != nil {
			cli.Log.Warnf("Received call offer_nack for stanza id %s", ag.OptionalString("id"))
		}
		return
	}
	if ackType != types.SignalingOffer {
		return
	}
	if cli.callManager == nil {
		return
	}

	stanzaID := ag.String("id")
	if stanzaID == "" {
		return
	}

	callID, ok := cli.callManager.ResolveCallIDByOfferStanzaID(stanzaID)
	if !ok {
		return
	}

	ackData := ParseOfferAckData(node)
	if ackData == nil {
		cli.Log.Debugf("Offer ack for %s had no parsable payload", callID)
		return
	}
	if err := cli.callManager.HandleOfferAck(callID, ackData); err != nil {
		cli.Log.Warnf("Failed to store offer ack relay data for %s: %v", callID, err)
		return
	}
	cli.cacheCallAckUserDevices(ackData.UserDevices)

	cli.dispatchEvent(&events.CallOfferAckRelay{
		CallID:             callID,
		StanzaID:           stanzaID,
		RelayData:          ackData.RelayData,
		RTE:                append([]byte(nil), ackData.RTE...),
		HasUploadFieldStat: ackData.HasUploadFieldStat,
		Joinable:           ackData.Joinable,
		VoIPSettingsByJID:  cloneVoIPSettingsByJID(ackData.VoIPSettingsByJID),
		UserDevices:        cloneUserDevicesByJID(ackData.UserDevices),
		Data:               node,
	})

	// Match WAWeb behavior: send relaylatency + transport immediately after
	// offer ACK relay allocation to speed up relay election and data path setup.
	if err := cli.callManager.SendRelayLatency(ctx, callID); err != nil {
		if cli.Log != nil {
			cli.Log.Warnf("Failed to send relay latency after offer ack for %s: %v", callID, err)
		}
	}
	if err := cli.callManager.SendTransport(ctx, callID); err != nil {
		if cli.Log != nil {
			cli.Log.Warnf("Failed to send transport signaling after offer ack for %s: %v", callID, err)
		}
	}

	cli.ensureCallTransportAsync(ctx, callID, "offer_ack")
}
