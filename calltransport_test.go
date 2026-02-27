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
	"net"
	"testing"
	"time"

	"go.mau.fi/whatsmeow/types"
)

func TestSelectBestRelayAddressPrefersLowerRTT(t *testing.T) {
	slow := uint32(120)
	fast := uint32(15)

	relayData := &types.RelayData{
		Endpoints: []types.RelayEndpoint{
			{
				RelayName: "slow",
				C2RRTTMs:  &slow,
				Addresses: []types.RelayAddress{{IPv4: "10.0.0.10", Port: 3480}},
			},
			{
				RelayName: "fast",
				C2RRTTMs:  &fast,
				Addresses: []types.RelayAddress{{IPv4: "10.0.0.20", Port: 3480}},
			},
		},
	}

	endpoint, address, err := selectBestRelayAddress(relayData)
	if err != nil {
		t.Fatalf("selectBestRelayAddress failed: %v", err)
	}
	if endpoint.RelayName != "fast" {
		t.Fatalf("unexpected selected relay: got %s want fast", endpoint.RelayName)
	}
	if address.IPv4 != "10.0.0.20" {
		t.Fatalf("unexpected selected relay address: got %s want 10.0.0.20", address.IPv4)
	}
}

func TestNoopCallTransportFailsFast(t *testing.T) {
	transport := &NoopCallTransport{}
	info := &types.CallInfo{CallID: "call-noop"}
	if err := transport.Connect(context.Background(), info); !errors.Is(err, ErrCallTransportNotConfigured) {
		t.Fatalf("expected ErrCallTransportNotConfigured on connect, got %v", err)
	}
	if err := transport.Send(context.Background(), info, []byte("x")); !errors.Is(err, ErrCallTransportNotConfigured) {
		t.Fatalf("expected ErrCallTransportNotConfigured on send, got %v", err)
	}
}

func TestRelayUDPCallTransportSendAndClose(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create UDP listener: %v", err)
	}
	defer pc.Close()

	addr := pc.LocalAddr().(*net.UDPAddr)
	relayData := &types.RelayData{
		Endpoints: []types.RelayEndpoint{{
			RelayName: "local",
			Addresses: []types.RelayAddress{{
				IPv4: "127.0.0.1",
				Port: uint16(addr.Port),
			}},
		}},
	}
	callInfo := &types.CallInfo{CallID: "call-udp-send", RelayData: relayData}
	transport := NewRelayUDPCallTransport(RelayUDPCallTransportConfig{DialTimeout: time.Second, ReadBufferSize: 512})

	if err = transport.Connect(context.Background(), callInfo); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	received := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, readErr := pc.ReadFrom(buf)
		if readErr != nil {
			return
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		received <- payload
	}()

	outbound := []byte("phase2-payload")
	if err = transport.Send(context.Background(), callInfo, outbound); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	select {
	case got := <-received:
		if !bytes.Equal(got, outbound) {
			t.Fatalf("unexpected UDP payload: got %q want %q", got, outbound)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for UDP payload")
	}

	if err = transport.Close(context.Background(), callInfo); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if err = transport.Send(context.Background(), callInfo, []byte("after-close")); err == nil {
		t.Fatalf("expected send to fail after close")
	}
}

func TestRelayUDPCallTransportIncomingHandler(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create UDP listener: %v", err)
	}
	defer pc.Close()

	addr := pc.LocalAddr().(*net.UDPAddr)
	relayData := &types.RelayData{
		Endpoints: []types.RelayEndpoint{{
			RelayName: "local",
			Addresses: []types.RelayAddress{{
				IPv4: "127.0.0.1",
				Port: uint16(addr.Port),
			}},
		}},
	}
	callInfo := &types.CallInfo{CallID: "call-udp-inbound", RelayData: relayData}
	transport := NewRelayUDPCallTransport(RelayUDPCallTransportConfig{DialTimeout: time.Second, ReadBufferSize: 512})

	incoming := make(chan []byte, 1)
	transport.SetIncomingHandler(func(callID string, payload []byte) {
		if callID != callInfo.CallID {
			return
		}
		copied := make([]byte, len(payload))
		copy(copied, payload)
		incoming <- copied
	})

	if err = transport.Connect(context.Background(), callInfo); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		buf := make([]byte, 64)
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, sourceAddr, readErr := pc.ReadFrom(buf)
		if readErr != nil {
			return
		}
		if string(buf[:n]) != "ping" {
			return
		}
		_, _ = pc.WriteTo([]byte("pong"), sourceAddr)
	}()

	if err = transport.Send(context.Background(), callInfo, []byte("ping")); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	select {
	case got := <-incoming:
		if !bytes.Equal(got, []byte("pong")) {
			t.Fatalf("unexpected inbound payload: got %q want %q", got, []byte("pong"))
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for inbound payload callback")
	}

	<-serverDone
	_ = transport.Close(context.Background(), callInfo)
}
