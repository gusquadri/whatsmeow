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
	"net"
	"strconv"
	"sync"
	"time"

	"go.mau.fi/whatsmeow/types"
)

const (
	defaultRelayDialTimeout = 5 * time.Second
	defaultRelayReadBufSize = 2048
	defaultRelayPort        = 3480
)

// ErrCallTransportNotConfigured is returned when call transport is still using
// the default placeholder implementation.
var ErrCallTransportNotConfigured = errors.New("call transport is not configured")

// IncomingCallTransportPayloadHandler handles inbound transport payloads.
type IncomingCallTransportPayloadHandler func(callID string, payload []byte)

// CallTransport is the Phase 2 transport abstraction.
//
// Implementations should establish and maintain a relay-backed data path for a
// specific call. The manager sets a payload handler to consume inbound packets.
type CallTransport interface {
	Connect(ctx context.Context, info *types.CallInfo) error
	Close(ctx context.Context, info *types.CallInfo) error
	Send(ctx context.Context, info *types.CallInfo, payload []byte) error
	SetIncomingHandler(handler IncomingCallTransportPayloadHandler)
}

// NoopCallTransport is a safe default transport used until a concrete Phase 2
// transport implementation is configured.
type NoopCallTransport struct{}

func (n *NoopCallTransport) Connect(context.Context, *types.CallInfo) error {
	return ErrCallTransportNotConfigured
}
func (n *NoopCallTransport) Close(context.Context, *types.CallInfo) error { return nil }
func (n *NoopCallTransport) Send(context.Context, *types.CallInfo, []byte) error {
	return ErrCallTransportNotConfigured
}
func (n *NoopCallTransport) SetIncomingHandler(IncomingCallTransportPayloadHandler) {}

// RelayUDPCallTransportConfig configures RelayUDPCallTransport.
type RelayUDPCallTransportConfig struct {
	DialTimeout    time.Duration
	ReadBufferSize int
}

type relayConn struct {
	conn net.Conn
}

// RelayUDPCallTransport is a concrete Phase 2 transport adapter that connects
// to elected relay endpoints over UDP and forwards inbound payloads to the
// configured handler.
//
// This is a real transport adapter replacing the previous no-op behavior. It
// provides relay-backed packet IO suitable for the current signaling/media
// integration points while keeping WebRTC-specific logic for later phases.
type RelayUDPCallTransport struct {
	cfg      RelayUDPCallTransportConfig
	incoming IncomingCallTransportPayloadHandler

	mu    sync.RWMutex
	conns map[string]*relayConn
}

// NewRelayUDPCallTransport creates a UDP relay transport with sane defaults.
func NewRelayUDPCallTransport(cfg RelayUDPCallTransportConfig) *RelayUDPCallTransport {
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = defaultRelayDialTimeout
	}
	if cfg.ReadBufferSize <= 0 {
		cfg.ReadBufferSize = defaultRelayReadBufSize
	}
	return &RelayUDPCallTransport{
		cfg:   cfg,
		conns: make(map[string]*relayConn),
	}
}

// SetIncomingHandler sets the inbound payload callback.
func (t *RelayUDPCallTransport) SetIncomingHandler(handler IncomingCallTransportPayloadHandler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.incoming = handler
}

// Connect opens a UDP connection for the call to the best available relay endpoint.
func (t *RelayUDPCallTransport) Connect(ctx context.Context, info *types.CallInfo) error {
	if info == nil {
		return fmt.Errorf("call info is nil")
	}
	if info.CallID == "" {
		return fmt.Errorf("call id is required")
	}

	t.mu.RLock()
	if _, ok := t.conns[info.CallID]; ok {
		t.mu.RUnlock()
		return nil
	}
	t.mu.RUnlock()

	endpoint, addr, err := selectBestRelayAddress(info.RelayData)
	if err != nil {
		return err
	}

	host := addr.IPv4
	port := addr.Port
	if host == "" {
		host = addr.IPv6
		if addr.PortV6 != 0 {
			port = addr.PortV6
		}
	}
	if host == "" {
		return fmt.Errorf("relay %s has no usable host", endpoint.RelayName)
	}
	if port == 0 {
		port = defaultRelayPort
	}
	remote := net.JoinHostPort(host, strconv.Itoa(int(port)))

	dialTimeout := t.cfg.DialTimeout
	if dl, ok := ctx.Deadline(); ok {
		if remain := time.Until(dl); remain > 0 && remain < dialTimeout {
			dialTimeout = remain
		}
	}

	dialer := net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "udp", remote)
	if err != nil {
		return fmt.Errorf("failed to dial relay %s (%s): %w", endpoint.RelayName, remote, err)
	}

	rc := &relayConn{conn: conn}

	t.mu.Lock()
	if _, exists := t.conns[info.CallID]; exists {
		t.mu.Unlock()
		_ = conn.Close()
		return nil
	}
	t.conns[info.CallID] = rc
	t.mu.Unlock()

	go t.readLoop(info.CallID, rc)
	return nil
}

// Send writes a payload to the connected relay socket for a call.
func (t *RelayUDPCallTransport) Send(ctx context.Context, info *types.CallInfo, payload []byte) error {
	if info == nil {
		return fmt.Errorf("call info is nil")
	}
	if len(payload) == 0 {
		return nil
	}

	t.mu.RLock()
	rc := t.conns[info.CallID]
	t.mu.RUnlock()
	if rc == nil || rc.conn == nil {
		return fmt.Errorf("call %s transport is not connected", info.CallID)
	}

	if dl, ok := ctx.Deadline(); ok {
		if err := rc.conn.SetWriteDeadline(dl); err != nil {
			return fmt.Errorf("failed to set write deadline: %w", err)
		}
	} else {
		_ = rc.conn.SetWriteDeadline(time.Time{})
	}

	_, err := rc.conn.Write(payload)
	if err != nil {
		return fmt.Errorf("failed to send relay payload: %w", err)
	}
	return nil
}

func (t *RelayUDPCallTransport) readLoop(callID string, rc *relayConn) {
	buf := make([]byte, t.cfg.ReadBufferSize)
	for {
		n, err := rc.conn.Read(buf)
		if n > 0 {
			t.mu.RLock()
			handler := t.incoming
			t.mu.RUnlock()
			if handler != nil {
				payload := make([]byte, n)
				copy(payload, buf[:n])
				handler(callID, payload)
			}
		}
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			break
		}
	}

	t.mu.Lock()
	if current, ok := t.conns[callID]; ok && current == rc {
		delete(t.conns, callID)
	}
	t.mu.Unlock()
}

// Close closes the UDP connection for the call.
func (t *RelayUDPCallTransport) closeByCallID(callID string) error {
	t.mu.Lock()
	rc, ok := t.conns[callID]
	if ok {
		delete(t.conns, callID)
	}
	t.mu.Unlock()
	if !ok || rc == nil || rc.conn == nil {
		return nil
	}
	if err := rc.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("failed to close relay transport for %s: %w", callID, err)
	}
	return nil
}

func (t *RelayUDPCallTransport) Close(ctx context.Context, info *types.CallInfo) error {
	if info == nil {
		return nil
	}
	return t.closeByCallID(info.CallID)
}

func selectBestRelayAddress(relayData *types.RelayData) (*types.RelayEndpoint, *types.RelayAddress, error) {
	if relayData == nil {
		return nil, nil, fmt.Errorf("relay data is nil")
	}
	if len(relayData.Endpoints) == 0 {
		return nil, nil, fmt.Errorf("relay data has no endpoints")
	}

	var (
		bestEndpoint *types.RelayEndpoint
		bestAddress  *types.RelayAddress
		bestScore    uint32 = ^uint32(0)
	)

	for i := range relayData.Endpoints {
		ep := &relayData.Endpoints[i]
		if len(ep.Addresses) == 0 {
			continue
		}
		address := chooseAddress(ep.Addresses)
		if address == nil {
			continue
		}

		score := uint32(^uint32(0) - 1)
		if ep.C2RRTTMs != nil {
			score = *ep.C2RRTTMs
		}
		if bestEndpoint == nil || score < bestScore {
			bestEndpoint = ep
			bestAddress = address
			bestScore = score
		}
	}

	if bestEndpoint == nil || bestAddress == nil {
		return nil, nil, fmt.Errorf("relay endpoints contain no usable addresses")
	}
	return bestEndpoint, bestAddress, nil
}

func chooseAddress(addrs []types.RelayAddress) *types.RelayAddress {
	for i := range addrs {
		a := &addrs[i]
		if a.IPv4 != "" {
			return a
		}
	}
	for i := range addrs {
		a := &addrs[i]
		if a.IPv6 != "" {
			return a
		}
	}
	return nil
}
