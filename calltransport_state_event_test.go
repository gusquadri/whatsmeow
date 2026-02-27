// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

func TestSetCallTransportDispatchesWebRTCStateEvents(t *testing.T) {
	cli := &Client{}
	cm := NewCallManager(cli)
	cli.callManager = cm

	relayRTT := uint32(10)
	callID := "call-state-events-1"
	cm.calls[callID] = &types.CallInfo{
		CallID: callID,
		RelayData: &types.RelayData{
			RelayKey:    []byte("relay-key"),
			RelayTokens: [][]byte{[]byte("relay-token")},
			AuthTokens:  [][]byte{[]byte("auth-token")},
			Endpoints: []types.RelayEndpoint{
				{
					RelayName:   "relay-a",
					RelayID:     1,
					TokenID:     0,
					AuthTokenID: 0,
					C2RRTTMs:    &relayRTT,
					Addresses: []types.RelayAddress{
						{Protocol: 0, IPv4: "10.0.0.1", Port: 3480},
					},
				},
			},
		},
	}

	evtCh := make(chan *events.CallWebRTCTransportState, 4)
	handlerID := cli.AddEventHandler(func(evt any) {
		if stateEvt, ok := evt.(*events.CallWebRTCTransportState); ok {
			select {
			case evtCh <- stateEvt:
			default:
			}
		}
	})
	defer cli.RemoveEventHandler(handlerID)

	factory := WebRTCRelaySessionFactoryFunc(func(context.Context, *types.CallInfo, WebRTCRelayConnectionInfo) (WebRTCRelaySession, error) {
		return nil, errors.New("forced connect error")
	})
	transport := NewWebRTCRelayCallTransport(WebRTCRelayCallTransportConfig{SessionFactory: factory})
	if err := cli.SetCallTransport(transport); err != nil {
		t.Fatalf("SetCallTransport failed: %v", err)
	}

	if err := cm.EnsureTransport(context.Background(), callID); err == nil {
		t.Fatalf("expected EnsureTransport to fail")
	}

	timeout := time.After(2 * time.Second)
	gotFailed := false
	for !gotFailed {
		select {
		case evt := <-evtCh:
			if evt.CallID != callID {
				continue
			}
			if evt.State == WebRTCTransportStateFailed.String() && evt.Reason != "" {
				gotFailed = true
			}
		case <-timeout:
			t.Fatalf("timed out waiting for failed WebRTC state event")
		}
	}
}
