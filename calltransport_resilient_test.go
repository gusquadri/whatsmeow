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
)

type flakyTransport struct {
	failFor     int
	sendCalls   int
	connects    int
	closes      int
	incomingSet bool
}

func (f *flakyTransport) Connect(context.Context, *types.CallInfo) error {
	f.connects++
	return nil
}
func (f *flakyTransport) Close(context.Context, *types.CallInfo) error {
	f.closes++
	return nil
}
func (f *flakyTransport) Send(context.Context, *types.CallInfo, []byte) error {
	f.sendCalls++
	if f.sendCalls <= f.failFor {
		return errors.New("simulated send error")
	}
	return nil
}
func (f *flakyTransport) SetIncomingHandler(IncomingCallTransportPayloadHandler) {
	f.incomingSet = true
}

func TestResilientCallTransportRetriesAndReconnects(t *testing.T) {
	base := &flakyTransport{failFor: 2}
	transport := NewResilientCallTransport(ResilientCallTransportConfig{
		Base:               base,
		SendRetries:        3,
		RetryBackoff:       time.Millisecond,
		ReconnectOnFailure: true,
	})
	transport.SetIncomingHandler(func(string, []byte) {})
	if !base.incomingSet {
		t.Fatalf("expected incoming handler to be forwarded")
	}

	if err := transport.Send(context.Background(), &types.CallInfo{CallID: "call"}, []byte("data")); err != nil {
		t.Fatalf("Send should succeed after retries: %v", err)
	}
	if base.sendCalls != 3 {
		t.Fatalf("unexpected send call count: %d", base.sendCalls)
	}
	if base.connects == 0 || base.closes == 0 {
		t.Fatalf("expected reconnect behavior, got connects=%d closes=%d", base.connects, base.closes)
	}
}

func TestResilientCallTransportFailsAfterRetryBudget(t *testing.T) {
	base := &flakyTransport{failFor: 10}
	transport := NewResilientCallTransport(ResilientCallTransportConfig{Base: base, SendRetries: 2, RetryBackoff: time.Millisecond})
	err := transport.Send(context.Background(), &types.CallInfo{CallID: "call"}, []byte("data"))
	if err == nil {
		t.Fatalf("expected send to fail after retries")
	}
	if base.sendCalls != 3 {
		t.Fatalf("unexpected send calls: got %d want 3", base.sendCalls)
	}
}
