//go:build pionwebrtc

// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/interceptor"
	"github.com/pion/logging"
	"github.com/pion/webrtc/v4"
	"go.mau.fi/whatsmeow/types"
)

type pionWebRTCRelaySession struct {
	pc *webrtc.PeerConnection
	dc *webrtc.DataChannel

	relay                WebRTCRelayConnectionInfo
	stunCreds            StunCredentials
	stunCredProfiles     []StunCredentials
	stunSenderSub        []byte
	stunControlling      bool
	tieBreaker           uint64
	keepaliveInterval    time.Duration
	outOfBandSTUNRefresh bool
	muxConn              net.PacketConn

	keepaliveCancel context.CancelFunc
	keepaliveWG     sync.WaitGroup
	closeOnce       sync.Once

	attemptID     string
	attemptSource string
	connected     atomic.Bool

	mu       sync.RWMutex
	incoming func(payload []byte)
}

const (
	preflightSTUNBurstRetries   = 3
	preflightSTUNBurstInterval  = 180 * time.Millisecond
	preConnectBindRetryInterval = 350 * time.Millisecond
)

func pionTracef(format string, args ...any) {
	log.Printf("whatsmeow-call DEBUG: "+format, args...)
}

func (s *pionWebRTCRelaySession) Send(_ context.Context, payload []byte) error {
	if s.dc == nil {
		return fmt.Errorf("data channel is nil")
	}
	if s.dc.ReadyState() != webrtc.DataChannelStateOpen {
		return fmt.Errorf("data channel is not open: %s", s.dc.ReadyState())
	}
	return s.dc.Send(payload)
}

func (s *pionWebRTCRelaySession) closeResources(reason string) error {
	var closeErr error
	s.closeOnce.Do(func() {
		s.connected.Store(false)
		pionTracef("session close start attempt=%s source=%s relay=%s#%d@%s:%d reason=%s",
			s.attemptID,
			s.attemptSource,
			s.relay.RelayName,
			s.relay.RelayID,
			s.relay.IP,
			s.relay.Port,
			reason,
		)
		if s.keepaliveCancel != nil {
			s.keepaliveCancel()
			s.keepaliveWG.Wait()
		}
		if s.dc != nil {
			_ = s.dc.Close()
		}
		if s.pc != nil {
			if err := s.pc.Close(); err != nil {
				closeErr = err
			}
		}
		if s.muxConn != nil {
			pionTracef("closing mux socket attempt=%s source=%s relay=%s#%d local_addr=%v reason=%s",
				s.attemptID,
				s.attemptSource,
				s.relay.RelayName,
				s.relay.RelayID,
				s.muxConn.LocalAddr(),
				reason,
			)
			_ = s.muxConn.Close()
		}
		pionTracef("session close finished attempt=%s source=%s relay=%s#%d@%s:%d reason=%s err=%v",
			s.attemptID,
			s.attemptSource,
			s.relay.RelayName,
			s.relay.RelayID,
			s.relay.IP,
			s.relay.Port,
			reason,
			closeErr,
		)
	})
	return closeErr
}

func (s *pionWebRTCRelaySession) Close(context.Context) error {
	return s.closeResources("transport_close")
}

func (s *pionWebRTCRelaySession) SetIncomingHandler(handler func(payload []byte)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.incoming = handler
}

func (s *pionWebRTCRelaySession) handleIncoming(payload []byte) {
	s.mu.RLock()
	h := s.incoming
	s.mu.RUnlock()
	if h == nil || len(payload) == 0 {
		return
	}
	copied := make([]byte, len(payload))
	copy(copied, payload)
	h(copied)
}

func (s *pionWebRTCRelaySession) startOutOfBandSTUNKeepalive() {
	if !s.outOfBandSTUNRefresh || s.keepaliveInterval <= 0 || len(s.stunCreds.Username) == 0 {
		return
	}
	if s.keepaliveCancel != nil {
		return
	}
	baseCtx := withCallTransportAttemptTrace(context.Background(), s.attemptID, s.attemptSource)
	ctx, cancel := context.WithCancel(baseCtx)
	s.keepaliveCancel = cancel
	s.keepaliveWG.Add(1)
	profiles := s.stunCredProfiles
	if len(profiles) == 0 {
		profiles = []StunCredentials{s.stunCreds}
	}
	sendRefresh := func(refreshCtx context.Context) {
		for _, creds := range profiles {
			if len(creds.Username) == 0 || len(creds.IntegrityKey) == 0 {
				continue
			}
			if s.muxConn != nil {
				// Keep relay binding alive on the same 5-tuple used by ICE.
				_ = sendPreflightSTUNOnConn(refreshCtx, s.muxConn, s.relay, creds, s.stunSenderSub, s.tieBreaker, s.stunControlling)
			} else {
				_ = attemptWebRTCPreflightSTUNWithAttrs(
					refreshCtx,
					s.relay,
					creds,
					s.stunSenderSub,
					s.tieBreaker,
					s.stunControlling,
				)
			}
		}
	}
	go func() {
		defer s.keepaliveWG.Done()
		initialCtx, initialCancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		sendRefresh(initialCtx)
		initialCancel()
		for {
			nextInterval := s.keepaliveInterval
			if !s.connected.Load() {
				nextInterval = preConnectBindRetryInterval
			}
			if nextInterval <= 0 {
				nextInterval = 500 * time.Millisecond
			}
			timer := time.NewTimer(nextInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}

			refreshTimeout := 3 * time.Second
			if !s.connected.Load() {
				refreshTimeout = 1500 * time.Millisecond
			}
			refreshCtx, refreshCancel := context.WithTimeout(ctx, refreshTimeout)
			sendRefresh(refreshCtx)
			refreshCancel()
		}
	}()
}

func setSessionConnectedState(session *pionWebRTCRelaySession, state bool) {
	if session == nil {
		return
	}
	if state {
		session.connected.Store(true)
	} else {
		session.connected.Store(false)
	}
}

func markSessionConnected(session *pionWebRTCRelaySession) {
	setSessionConnectedState(session, true)
}

func markSessionDisconnected(session *pionWebRTCRelaySession) {
	setSessionConnectedState(session, false)
}

// newPionWebRTCAPI creates a Pion WebRTC API instance. When existingConn is
// non-nil it is used as the ICE UDP mux socket instead of creating a new one.
// This allows the caller to share a socket between STUN preflight and Pion ICE
// so that the relay binding (keyed on source IP:port) matches.
func newPionWebRTCAPI(cfg PionWebRTCSessionConfig, existingConn net.PacketConn) (*webrtc.API, net.PacketConn, error) {
	setting := webrtc.SettingEngine{}
	if cfg.DisableMDNS {
		setting.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	}
	if cfg.ForceUDP4Only {
		setting.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	}
	if cfg.DisableFingerprint {
		setting.DisableCertificateFingerprintVerification(true)
	}
	if cfg.ForceDTLSClientRole {
		if err := setting.SetAnsweringDTLSRole(webrtc.DTLSRoleClient); err != nil {
			return nil, nil, err
		}
	}
	if cfg.ICEDisconnectedAfter > 0 && cfg.ICEFailedAfter > 0 && cfg.ICEKeepaliveInterval > 0 {
		setting.SetICETimeouts(cfg.ICEDisconnectedAfter, cfg.ICEFailedAfter, cfg.ICEKeepaliveInterval)
	}

	var muxConn net.PacketConn
	if cfg.UseUDPMux {
		if existingConn != nil {
			muxConn = existingConn
		} else {
			addr := cfg.UDPMuxListenAddr
			if addr == "" {
				if cfg.ForceUDP4Only {
					addr = "0.0.0.0:0"
				} else {
					addr = ":0"
				}
			}
			network := "udp"
			if cfg.ForceUDP4Only {
				network = "udp4"
			}
			conn, err := net.ListenPacket(network, addr)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create UDP mux listener: %w", err)
			}
			muxConn = conn
		}
		loggerFactory := logging.NewDefaultLoggerFactory()
		setting.SetICEUDPMux(webrtc.NewICEUDPMux(loggerFactory.NewLogger("whatsmeow-call"), muxConn))
	}

	media := &webrtc.MediaEngine{}
	if err := media.RegisterDefaultCodecs(); err != nil {
		if muxConn != nil && existingConn == nil {
			_ = muxConn.Close()
		}
		return nil, nil, fmt.Errorf("failed to register default codecs: %w", err)
	}
	registry := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(media, registry); err != nil {
		if muxConn != nil && existingConn == nil {
			_ = muxConn.Close()
		}
		return nil, nil, fmt.Errorf("failed to register default interceptors: %w", err)
	}

	api := webrtc.NewAPI(
		webrtc.WithSettingEngine(setting),
		webrtc.WithMediaEngine(media),
		webrtc.WithInterceptorRegistry(registry),
	)
	return api, muxConn, nil
}

// NewPionWebRTCRelaySessionFactory builds a Pion-backed WebRTC relay session factory.
func NewPionWebRTCRelaySessionFactory(cfg PionWebRTCSessionConfig) (WebRTCRelaySessionFactory, error) {
	cfg = normalizePionWebRTCSessionConfig(cfg)
	if cfg.TieBreaker == 0 {
		if tieBreaker, err := randomUint64(); err == nil {
			cfg.TieBreaker = tieBreaker
		} else {
			cfg.TieBreaker = 0x0102030405060708
		}
	}

	factory := WebRTCRelaySessionFactoryFunc(func(ctx context.Context, info *types.CallInfo, relay WebRTCRelayConnectionInfo) (WebRTCRelaySession, error) {
		if info == nil {
			return nil, fmt.Errorf("call info is nil")
		}
		attemptID, attemptSource := callTransportAttemptTraceFromContext(ctx)
		if attemptID == "" {
			attemptID = "unknown"
		}
		if attemptSource == "" {
			attemptSource = "unknown"
		}
		pionTracef(
			"session init call=%s attempt=%s source=%s relay=%s#%d@%s:%d",
			info.CallID,
			attemptID,
			attemptSource,
			relay.RelayName,
			relay.RelayID,
			relay.IP,
			relay.Port,
		)
		effectiveCfg := cfg
		if cfg.ForceUDP4Only && strings.Contains(relay.IP, ":") {
			// Prefer UDP4 by default, but fall back to dual-stack for IPv6 relay
			// candidates. Some environments can reach WA relays only over IPv6.
			effectiveCfg.ForceUDP4Only = false
			if effectiveCfg.UDPMuxListenAddr == "" || effectiveCfg.UDPMuxListenAddr == "0.0.0.0:0" {
				effectiveCfg.UDPMuxListenAddr = ":0"
			}
			pionTracef(
				"session ipv6 relay fallback call=%s attempt=%s source=%s relay=%s#%d@%s:%d force_udp4_only=false listen_addr=%s",
				info.CallID,
				attemptID,
				attemptSource,
				relay.RelayName,
				relay.RelayID,
				relay.IP,
				relay.Port,
				effectiveCfg.UDPMuxListenAddr,
			)
		}
		stunProfiles := stunCredentialProfilesFromRelay(relay, effectiveCfg.EnableCredentialVariantFallback)
		stunCreds := StunCredentials{}
		selectedProfileLabel := ""
		for _, profile := range stunProfiles {
			if len(profile.creds.Username) == 0 || len(profile.creds.IntegrityKey) == 0 {
				continue
			}
			stunCreds = profile.creds
			selectedProfileLabel = profile.label
			break
		}
		if len(stunCreds.Username) == 0 || len(stunCreds.IntegrityKey) == 0 {
			pionTracef(
				"session reject call=%s attempt=%s source=%s relay=%s#%d@%s:%d reason=missing_stun_credentials",
				info.CallID,
				attemptID,
				attemptSource,
				relay.RelayName,
				relay.RelayID,
				relay.IP,
				relay.Port,
			)
			return nil, fmt.Errorf("relay %s is missing stun credentials", relay.RelayName)
		}
		pionTracef(
			"session credentials call=%s attempt=%s source=%s relay=%s#%d auth_token_id=%d token_id=%d profile=%s ufrag=%s pwd=%s",
			info.CallID,
			attemptID,
			attemptSource,
			relay.RelayName,
			relay.RelayID,
			relay.AuthTokenID,
			relay.TokenID,
			selectedProfileLabel,
			credentialDebugPreview(relay.AuthToken),
			credentialDebugPreview(relay.RelayKey),
		)
		senderSub := buildSTUNSenderSubscriptions(info)
		controlling := info.IsInitiator

		// Create UDP socket early so STUN preflight and Pion ICE share the same
		// source port. The relay binds based on source IP:port — if the preflight
		// creates a binding from port X but Pion sends ICE checks from port Y, the
		// relay won't recognize port Y and ICE fails.
		var sharedConn net.PacketConn
		if effectiveCfg.UseUDPMux {
			addr := effectiveCfg.UDPMuxListenAddr
			if addr == "" {
				if effectiveCfg.ForceUDP4Only {
					addr = "0.0.0.0:0"
				} else {
					addr = ":0"
				}
			}
			network := "udp"
			if effectiveCfg.ForceUDP4Only {
				network = "udp4"
			}
			conn, err := net.ListenPacket(network, addr)
			if err != nil {
				return nil, fmt.Errorf("failed to create shared UDP socket: %w", err)
			}
			sharedConn = conn
			pionTracef(
				"shared UDP socket created call=%s attempt=%s source=%s relay=%s#%d local_addr=%v",
				info.CallID,
				attemptID,
				attemptSource,
				relay.RelayName,
				relay.RelayID,
				sharedConn.LocalAddr(),
			)
		}

		if effectiveCfg.PreflightSTUN {
			if sharedConn != nil {
				// Use the shared socket so relay binding matches Pion's source port.
				pionTracef(
					"preflight STUN start(shared-socket) call=%s attempt=%s source=%s relay=%s#%d local_addr=%v profiles=%d retries=%d sender_sub_bytes=%d",
					info.CallID,
					attemptID,
					attemptSource,
					relay.RelayName,
					relay.RelayID,
					sharedConn.LocalAddr(),
					len(stunProfiles),
					preflightSTUNBurstRetries,
					len(senderSub),
				)
				_ = runPreflightSTUNBurstOnConn(ctx, sharedConn, relay, stunProfiles, senderSub, effectiveCfg.TieBreaker, controlling, info.CallID, attemptID, attemptSource)
			} else {
				pionTracef(
					"preflight STUN start(dial-socket) call=%s attempt=%s source=%s relay=%s#%d@%s:%d",
					info.CallID,
					attemptID,
					attemptSource,
					relay.RelayName,
					relay.RelayID,
					relay.IP,
					relay.Port,
				)
				_ = attemptPionWebRTCPreflightSTUN(ctx, relay, stunCreds, senderSub, effectiveCfg.TieBreaker, controlling)
			}
		}

		api, muxConn, err := newPionWebRTCAPI(effectiveCfg, sharedConn)
		if err != nil {
			if sharedConn != nil {
				_ = sharedConn.Close()
			}
			return nil, fmt.Errorf("failed to create pion api: %w", err)
		}
		if muxConn != nil {
			pionTracef(
				"ICE mux socket ready call=%s attempt=%s source=%s relay=%s#%d local_addr=%v",
				info.CallID,
				attemptID,
				attemptSource,
				relay.RelayName,
				relay.RelayID,
				muxConn.LocalAddr(),
			)
		}
		pc, err := api.NewPeerConnection(webrtc.Configuration{})
		if err != nil {
			if muxConn != nil {
				_ = muxConn.Close()
			}
			return nil, fmt.Errorf("failed to create peer connection: %w", err)
		}

		// Use browser-default channel negotiation (DCEP/in-band) for closer
		// WAWeb parity. Forced negotiated channels can deadlock if the peer
		// doesn't pre-create a matching id.
		dc, err := pc.CreateDataChannel(WhatsAppWebDataChannelName, nil)
		if err != nil {
			_ = pc.Close()
			if muxConn != nil {
				_ = muxConn.Close()
			}
			return nil, fmt.Errorf("failed to create data channel: %w", err)
		}

		session := &pionWebRTCRelaySession{
			pc:                   pc,
			dc:                   dc,
			relay:                relay,
			stunCreds:            stunCreds,
			stunCredProfiles:     stunCredentialProfileCreds(stunProfiles),
			stunSenderSub:        senderSub,
			stunControlling:      controlling,
			tieBreaker:           effectiveCfg.TieBreaker,
			keepaliveInterval:    effectiveCfg.KeepaliveInterval,
			outOfBandSTUNRefresh: effectiveCfg.OutOfBandSTUNRefresh,
			muxConn:              muxConn,
			attemptID:            attemptID,
			attemptSource:        attemptSource,
		}
		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			session.handleIncoming(msg.Data)
		})

		openCh := make(chan struct{}, 1)
		dc.OnOpen(func() {
			markSessionConnected(session)
			pionTracef(
				"data channel opened call=%s attempt=%s source=%s relay=%s#%d@%s:%d",
				info.CallID,
				attemptID,
				attemptSource,
				relay.RelayName,
				relay.RelayID,
				relay.IP,
				relay.Port,
			)
			select {
			case openCh <- struct{}{}:
			default:
			}
		})

		failCh := make(chan error, 1)
		dc.OnClose(func() {
			markSessionDisconnected(session)
			pionTracef(
				"data channel closed call=%s attempt=%s source=%s relay=%s#%d@%s:%d",
				info.CallID,
				attemptID,
				attemptSource,
				relay.RelayName,
				relay.RelayID,
				relay.IP,
				relay.Port,
			)
			select {
			case failCh <- fmt.Errorf("data channel closed"):
			default:
			}
		})
		dc.OnError(func(err error) {
			pionTracef(
				"data channel error call=%s attempt=%s source=%s relay=%s#%d@%s:%d err=%v",
				info.CallID,
				attemptID,
				attemptSource,
				relay.RelayName,
				relay.RelayID,
				relay.IP,
				relay.Port,
				err,
			)
			select {
			case failCh <- fmt.Errorf("data channel error: %w", err):
			default:
			}
		})
		pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
			if state == webrtc.ICEConnectionStateConnected || state == webrtc.ICEConnectionStateCompleted {
				markSessionConnected(session)
			}
			if state == webrtc.ICEConnectionStateFailed || state == webrtc.ICEConnectionStateClosed || state == webrtc.ICEConnectionStateDisconnected {
				markSessionDisconnected(session)
			}
			pionTracef(
				"ICE state call=%s attempt=%s source=%s relay=%s#%d@%s:%d state=%s",
				info.CallID,
				attemptID,
				attemptSource,
				relay.RelayName,
				relay.RelayID,
				relay.IP,
				relay.Port,
				state,
			)
			if state == webrtc.ICEConnectionStateFailed || state == webrtc.ICEConnectionStateClosed {
				select {
				case failCh <- fmt.Errorf("ice connection state changed: %s", state):
				default:
				}
			}
		})
		pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
			if state == webrtc.PeerConnectionStateConnected {
				markSessionConnected(session)
			}
			if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed || state == webrtc.PeerConnectionStateDisconnected {
				markSessionDisconnected(session)
			}
			pionTracef(
				"PeerConnection state call=%s attempt=%s source=%s relay=%s#%d@%s:%d state=%s",
				info.CallID,
				attemptID,
				attemptSource,
				relay.RelayName,
				relay.RelayID,
				relay.IP,
				relay.Port,
				state,
			)
			if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
				select {
				case failCh <- fmt.Errorf("peer connection state changed: %s", state):
				default:
				}
			}
		})

		offer, err := pc.CreateOffer(nil)
		if err != nil {
			_ = session.closeResources("create_offer_failed")
			return nil, fmt.Errorf("failed to create offer: %w", err)
		}
		if err = pc.SetLocalDescription(offer); err != nil {
			_ = session.closeResources("set_local_description_failed")
			return nil, fmt.Errorf("failed to set local description: %w", err)
		}

		modifiedSDP := ManipulateWebRTCOfferSDP(offer.SDP, relay)
		answer := webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: modifiedSDP}
		if err = pc.SetRemoteDescription(answer); err != nil {
			_ = session.closeResources("set_remote_description_failed")
			return nil, fmt.Errorf("failed to set manipulated remote answer: %w", err)
		}
		session.startOutOfBandSTUNKeepalive()

		waitCtx, cancel := context.WithTimeout(ctx, effectiveCfg.ConnectTimeout)
		defer cancel()
		select {
		case <-waitCtx.Done():
			_ = session.closeResources("connect_timeout")
			return nil, fmt.Errorf("webrtc connect timeout: %w", waitCtx.Err())
		case <-openCh:
			pionTracef(
				"session connected call=%s attempt=%s source=%s relay=%s#%d@%s:%d",
				info.CallID,
				attemptID,
				attemptSource,
				relay.RelayName,
				relay.RelayID,
				relay.IP,
				relay.Port,
			)
			return session, nil
		case err = <-failCh:
			_ = session.closeResources("state_failure")
			return nil, err
		}
	})
	return factory, nil
}

func attemptPionWebRTCPreflightSTUN(ctx context.Context, relay WebRTCRelayConnectionInfo, creds StunCredentials, senderSub []byte, tieBreaker uint64, controlling bool) error {
	return attemptWebRTCPreflightSTUNWithAttrs(ctx, relay, creds, senderSub, tieBreaker, controlling)
}

// attemptPreflightSTUNOnConn sends a STUN binding request through an existing
// PacketConn. This is used when the caller wants to share a socket between
// preflight and Pion ICE so the relay binding matches the same source port.
func attemptPreflightSTUNOnConn(ctx context.Context, conn net.PacketConn, relay WebRTCRelayConnectionInfo, creds StunCredentials, senderSub []byte, tieBreaker uint64, controlling bool) error {
	attemptID, source := callTransportAttemptTraceFromContext(ctx)
	if attemptID == "" {
		attemptID = "unknown"
	}
	if source == "" {
		source = "unknown"
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	packet, err := BuildStunBindingRequest(creds, senderSub, tieBreaker, controlling)
	if err != nil {
		return err
	}
	relayAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(relay.IP, fmt.Sprintf("%d", relay.Port)))
	if err != nil {
		return err
	}
	pionTracef(
		"preflight STUN send(shared-socket) attempt=%s source=%s relay=%s#%d@%s:%d local_addr=%v packet_bytes=%d",
		attemptID,
		source,
		relay.RelayName,
		relay.RelayID,
		relay.IP,
		relay.Port,
		conn.LocalAddr(),
		len(packet),
	)

	deadline := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err = conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	if _, err = conn.WriteTo(packet, relayAddr); err != nil {
		pionTracef("preflight STUN write failed(shared-socket) attempt=%s source=%s relay=%s#%d err=%v", attemptID, source, relay.RelayName, relay.RelayID, err)
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	readDeadline := time.Now().Add(2 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(readDeadline) {
		readDeadline = d
	}
	if err = conn.SetReadDeadline(readDeadline); err != nil {
		return err
	}
	buf := make([]byte, 2048)
	n, _, readErr := conn.ReadFrom(buf)
	// Clear deadlines so Pion's ICE agent isn't affected.
	_ = conn.SetWriteDeadline(time.Time{})
	_ = conn.SetReadDeadline(time.Time{})
	if readErr != nil {
		// Read timeout is acceptable — binding may still have been registered.
		pionTracef(
			"preflight STUN read timeout/err(shared-socket) attempt=%s source=%s relay=%s#%d local_addr=%v err=%v",
			attemptID,
			source,
			relay.RelayName,
			relay.RelayID,
			conn.LocalAddr(),
			readErr,
		)
		return nil
	}
	if n > 0 {
		_, _ = DecodeStunMessage(buf[:n])
	}
	pionTracef(
		"preflight STUN response(shared-socket) attempt=%s source=%s relay=%s#%d local_addr=%v bytes=%d",
		attemptID,
		source,
		relay.RelayName,
		relay.RelayID,
		conn.LocalAddr(),
		n,
	)
	return nil
}

// sendPreflightSTUNOnConn sends a STUN binding request using an existing mux
// socket without reading a response. This avoids racing with Pion's ICE read
// loop while still refreshing relay-side source-port bindings.
func sendPreflightSTUNOnConn(ctx context.Context, conn net.PacketConn, relay WebRTCRelayConnectionInfo, creds StunCredentials, senderSub []byte, tieBreaker uint64, controlling bool) error {
	attemptID, source := callTransportAttemptTraceFromContext(ctx)
	if attemptID == "" {
		attemptID = "unknown"
	}
	if source == "" {
		source = "unknown"
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	packet, err := BuildStunBindingRequest(creds, senderSub, tieBreaker, controlling)
	if err != nil {
		return err
	}
	relayAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(relay.IP, fmt.Sprintf("%d", relay.Port)))
	if err != nil {
		return err
	}
	pionTracef(
		"preflight STUN keepalive send(shared-socket) attempt=%s source=%s relay=%s#%d@%s:%d local_addr=%v packet_bytes=%d",
		attemptID,
		source,
		relay.RelayName,
		relay.RelayID,
		relay.IP,
		relay.Port,
		conn.LocalAddr(),
		len(packet),
	)
	deadline := time.Now().Add(2 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err = conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	_, err = conn.WriteTo(packet, relayAddr)
	_ = conn.SetWriteDeadline(time.Time{})
	return err
}

func runPreflightSTUNBurstOnConn(
	ctx context.Context,
	conn net.PacketConn,
	relay WebRTCRelayConnectionInfo,
	profiles []stunCredentialProfile,
	senderSub []byte,
	tieBreaker uint64,
	controlling bool,
	callID string,
	attemptID string,
	attemptSource string,
) error {
	if len(profiles) == 0 {
		return nil
	}
	for retry := 1; retry <= preflightSTUNBurstRetries; retry++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, profile := range profiles {
			if len(profile.creds.Username) == 0 || len(profile.creds.IntegrityKey) == 0 {
				continue
			}
			pionTracef(
				"preflight STUN profile(shared-socket) call=%s attempt=%s source=%s relay=%s#%d profile=%s retry=%d/%d",
				callID,
				attemptID,
				attemptSource,
				relay.RelayName,
				relay.RelayID,
				profile.label,
				retry,
				preflightSTUNBurstRetries,
			)
			if retry == 1 {
				// Probe once with a short read so we can log whether relay accepts
				// our credentials (server-reflexive style response).
				probeCtx, probeCancel := context.WithTimeout(ctx, 250*time.Millisecond)
				_ = attemptPreflightSTUNOnConn(probeCtx, conn, relay, profile.creds, senderSub, tieBreaker, controlling)
				probeCancel()
			} else {
				_ = sendPreflightSTUNOnConn(ctx, conn, relay, profile.creds, senderSub, tieBreaker, controlling)
			}
		}
		if retry == preflightSTUNBurstRetries {
			break
		}
		timer := time.NewTimer(preflightSTUNBurstInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}

func stunCredentialsFromRelay(relay WebRTCRelayConnectionInfo) StunCredentials {
	return StunCredentials{
		Username:     []byte(relay.AuthToken),
		IntegrityKey: []byte(relay.RelayKey),
	}
}

type stunCredentialProfile struct {
	label string
	creds StunCredentials
}

func stunCredentialProfilesFromRelay(relay WebRTCRelayConnectionInfo, enableFallback bool) []stunCredentialProfile {
	addProfile := func(profiles []stunCredentialProfile, dedupe map[string]struct{}, label string, creds StunCredentials) []stunCredentialProfile {
		if len(creds.Username) == 0 || len(creds.IntegrityKey) == 0 {
			return profiles
		}
		key := string(creds.Username) + "\x00" + string(creds.IntegrityKey)
		if _, ok := dedupe[key]; ok {
			return profiles
		}
		dedupe[key] = struct{}{}
		return append(profiles, stunCredentialProfile{label: label, creds: creds})
	}

	profiles := make([]stunCredentialProfile, 0, 4)
	dedupe := make(map[string]struct{}, 4)
	textCreds := stunCredentialsFromRelay(relay)
	profiles = addProfile(profiles, dedupe, "text", textCreds)
	if !enableFallback {
		return profiles
	}

	decodedCreds := StunCredentials{
		Username:     decodeMaybeBase64(relay.AuthToken),
		IntegrityKey: decodeMaybeBase64(relay.RelayKey),
	}
	profiles = addProfile(profiles, dedupe, "decoded", decodedCreds)
	profiles = addProfile(profiles, dedupe, "user_text_key_decoded", StunCredentials{
		Username:     textCreds.Username,
		IntegrityKey: decodedCreds.IntegrityKey,
	})
	profiles = addProfile(profiles, dedupe, "user_decoded_key_text", StunCredentials{
		Username:     decodedCreds.Username,
		IntegrityKey: textCreds.IntegrityKey,
	})
	return profiles
}

func credentialDebugPreview(value string) string {
	if value == "" {
		return "<empty>"
	}
	const limit = 14
	if len(value) <= limit*2 {
		return fmt.Sprintf("len=%d value=%s", len(value), value)
	}
	return fmt.Sprintf("len=%d value=%s...%s", len(value), value[:limit], value[len(value)-limit:])
}

func stunCredentialProfileCreds(profiles []stunCredentialProfile) []StunCredentials {
	if len(profiles) == 0 {
		return nil
	}
	out := make([]StunCredentials, 0, len(profiles))
	for _, profile := range profiles {
		out = append(out, profile.creds)
	}
	return out
}

func decodeMaybeBase64(input string) []byte {
	if input == "" {
		return nil
	}
	trimmed := strings.TrimSpace(input)
	if len(trimmed)%2 == 0 && isHexString(trimmed) {
		if decoded, err := hex.DecodeString(trimmed); err == nil && len(decoded) > 0 {
			return decoded
		}
	}
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(decoded) > 0 {
		return decoded
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil && len(decoded) > 0 {
		return decoded
	}
	raw := make([]byte, len(input))
	copy(raw, input)
	return raw
}

func buildSTUNSenderSubscriptions(info *types.CallInfo) []byte {
	callID := ""
	if info != nil {
		callID = info.CallID
	}
	audioLayer := StreamLayerAudio
	video0Layer := StreamLayerVideoStream0
	video1Layer := StreamLayerVideoStream1
	mediaPayload := PayloadTypeMedia
	descriptors := []SenderSubscription{
		{
			SSRC:        uint32Ptr(deriveSTUNSenderStreamSSRC(callID, "audio_media")),
			SSRCs:       []uint32{deriveSTUNSenderStreamSSRC(callID, "audio_fec"), deriveSTUNSenderStreamSSRC(callID, "audio_nack")},
			StreamLayer: &audioLayer,
			PayloadType: &mediaPayload,
		},
		{
			SSRC:        uint32Ptr(deriveSTUNSenderStreamSSRC(callID, "video0_media")),
			SSRCs:       []uint32{deriveSTUNSenderStreamSSRC(callID, "video0_fec"), deriveSTUNSenderStreamSSRC(callID, "video0_nack")},
			StreamLayer: &video0Layer,
			PayloadType: &mediaPayload,
		},
		{
			SSRC:        uint32Ptr(deriveSTUNSenderStreamSSRC(callID, "video1_media")),
			SSRCs:       []uint32{deriveSTUNSenderStreamSSRC(callID, "video1_fec"), deriveSTUNSenderStreamSSRC(callID, "video1_nack")},
			StreamLayer: &video1Layer,
			PayloadType: &mediaPayload,
		},
	}
	return SenderSubscriptions{Senders: descriptors}.Encode()
}

func deriveSTUNSenderSSRC(callID string) uint32 {
	if callID == "" {
		return 0x12345678
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(callID))
	v := h.Sum32()
	if v == 0 {
		return 0x12345678
	}
	return v
}

func deriveSTUNSenderStreamSSRC(callID string, suffix string) uint32 {
	base := callID
	if base == "" {
		base = "default"
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(base))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(suffix))
	v := h.Sum32()
	if v == 0 {
		return 0x12345678
	}
	return v
}

func uint32Ptr(v uint32) *uint32 {
	value := v
	return &value
}

func randomUint64() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

func attemptWebRTCPreflightSTUNWithAttrs(ctx context.Context, relay WebRTCRelayConnectionInfo, creds StunCredentials, senderSub []byte, tieBreaker uint64, controlling bool) error {
	attemptID, source := callTransportAttemptTraceFromContext(ctx)
	if attemptID == "" {
		attemptID = "unknown"
	}
	if source == "" {
		source = "unknown"
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	packet, err := BuildStunBindingRequest(
		creds,
		senderSub,
		tieBreaker,
		controlling,
	)
	if err != nil {
		return err
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(relay.IP, fmt.Sprintf("%d", relay.Port)))
	if err != nil {
		pionTracef("preflight STUN dial failed attempt=%s source=%s relay=%s#%d@%s:%d err=%v", attemptID, source, relay.RelayName, relay.RelayID, relay.IP, relay.Port, err)
		return err
	}
	defer conn.Close()
	pionTracef(
		"preflight STUN send(dial-socket) attempt=%s source=%s relay=%s#%d@%s:%d local_addr=%v packet_bytes=%d",
		attemptID,
		source,
		relay.RelayName,
		relay.RelayID,
		relay.IP,
		relay.Port,
		conn.LocalAddr(),
		len(packet),
	)
	if _, err = conn.Write(packet); err != nil {
		pionTracef("preflight STUN write failed(dial-socket) attempt=%s source=%s relay=%s#%d err=%v", attemptID, source, relay.RelayName, relay.RelayID, err)
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	readDeadline := time.Now().Add(2 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(readDeadline) {
		readDeadline = d
	}
	_ = conn.SetReadDeadline(readDeadline)
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		pionTracef(
			"preflight STUN read timeout/err(dial-socket) attempt=%s source=%s relay=%s#%d local_addr=%v err=%v",
			attemptID,
			source,
			relay.RelayName,
			relay.RelayID,
			conn.LocalAddr(),
			err,
		)
		return nil
	}
	if n > 0 {
		_, _ = DecodeStunMessage(buf[:n])
	}
	pionTracef(
		"preflight STUN response(dial-socket) attempt=%s source=%s relay=%s#%d local_addr=%v bytes=%d",
		attemptID,
		source,
		relay.RelayName,
		relay.RelayID,
		conn.LocalAddr(),
		n,
	)
	return nil
}

// AttemptWebRTCPreflightSTUN performs a STUN preflight to relay using WA attrs.
func AttemptWebRTCPreflightSTUN(ctx context.Context, relay WebRTCRelayConnectionInfo, username []byte, integrityKey []byte, tieBreaker uint64) error {
	return attemptWebRTCPreflightSTUNWithAttrs(
		ctx,
		relay,
		StunCredentials{Username: username, IntegrityKey: integrityKey},
		BuildAudioSenderSubscriptions(0x12345678),
		tieBreaker,
		true,
	)
}

// UsePionWebRTCTransport configures call transport to the Pion-backed WebRTC transport.
func (cli *Client) UsePionWebRTCTransport(cfg PionWebRTCSessionConfig) error {
	if cli.callManager == nil {
		return ErrNotLoggedIn
	}
	cfg = normalizePionWebRTCSessionConfig(cfg)
	factory, err := NewPionWebRTCRelaySessionFactory(cfg)
	if err != nil {
		return err
	}
	transport := NewWebRTCRelayCallTransport(WebRTCRelayCallTransportConfig{
		SessionFactory:                  factory,
		ConnectTimeout:                  cfg.ConnectTimeout,
		EnableCredentialVariantFallback: cfg.EnableCredentialVariantFallback,
	})
	return cli.SetCallTransport(transport)
}
