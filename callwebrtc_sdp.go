// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"go.mau.fi/whatsmeow/types"
)

const (
	// WhatsAppWebDataChannelName is the SCTP DataChannel label used by WhatsApp Web.
	WhatsAppWebDataChannelName = "wa-web-call"

	// WhatsAppWebDTLSFingerprint is the known fingerprint value injected by WhatsApp Web SDP manipulation.
	WhatsAppWebDTLSFingerprint = "sha-256 F9:CA:0C:98:A3:CC:71:D6:42:CE:5A:E2:53:D2:15:20:D3:1B:BA:D8:57:A4:F0:AF:BE:0B:FB:F3:6B:0C:A0:68"

	waRelayCandidatePriority = 2122262783
)

var (
	webRTCIceUfragRE  = regexp.MustCompile(`(?m)^a=ice-ufrag:[^\r\n]+`)
	webRTCIcePwdRE    = regexp.MustCompile(`(?m)^a=ice-pwd:[^\r\n]+`)
	webRTCFingerprint = regexp.MustCompile(`(?m)^a=fingerprint:[^\r\n]+`)
	webRTCSetupRE     = regexp.MustCompile(`(?m)^a=setup:[^\r\n]+`)
	webRTCIceOptionRE = regexp.MustCompile(`(?m)^a=ice-options:[^\r\n]+\r?\n`)
	webRTCCandidateRE = regexp.MustCompile(`(?m)^a=candidate:[^\r\n]+\r?\n`)
	webRTCEndOfCandRE = regexp.MustCompile(`(?m)^a=end-of-candidates\r?\n?`)
)

// WebRTCRelayConnectionInfo captures per-relay values needed by SDP manipulation
// and by the WebRTC data-path handshake.
type WebRTCRelayConnectionInfo struct {
	IP          string
	Port        uint16
	AuthToken   string
	RelayKey    string
	RelayName   string
	RelayID     uint32
	AuthTokenID uint32
	TokenID     uint32
	C2RRTTMs    *uint32
}

// ManipulateWebRTCOfferSDP applies WhatsApp-Web-style SDP surgery to a locally
// generated offer. This follows the same mutations used by the Rust reference.
func ManipulateWebRTCOfferSDP(offerSDP string, relay WebRTCRelayConnectionInfo) string {
	// Force setup:passive so our offerer side becomes the DTLS active (client).
	// Use regex instead of literal replacement to handle any setup value Pion emits.
	modified := webRTCSetupRE.ReplaceAllString(offerSDP, "a=setup:passive")
	modified = webRTCIceUfragRE.ReplaceAllString(modified, "a=ice-ufrag:"+relay.AuthToken)
	modified = webRTCIcePwdRE.ReplaceAllString(modified, "a=ice-pwd:"+relay.RelayKey)
	modified = webRTCFingerprint.ReplaceAllString(modified, "a=fingerprint:"+WhatsAppWebDTLSFingerprint)
	modified = webRTCIceOptionRE.ReplaceAllString(modified, "")
	modified = addRelayCandidateToSDP(modified, relay.IP, relay.Port)
	return modified
}

func addRelayCandidateToSDP(sdp, ip string, port uint16) string {
	modified := webRTCCandidateRE.ReplaceAllString(sdp, "")
	modified = webRTCEndOfCandRE.ReplaceAllString(modified, "")
	modified = ensureSDPTrailingNewline(modified)
	modified += fmt.Sprintf("a=candidate:2 1 udp %d %s %d typ host generation 0 network-cost 5\r\n", waRelayCandidatePriority, ip, port)
	modified += "a=end-of-candidates\r\n"
	return modified
}

func ensureSDPTrailingNewline(s string) string {
	if strings.HasSuffix(s, "\r\n") || strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\r\n"
}

func relayRTTForSort(c2r *uint32) uint32 {
	if c2r == nil {
		return math.MaxUint32
	}
	return *c2r
}

// ExtractWebRTCRelayConnectionInfo converts relay metadata from call signaling
// into a list of candidate WebRTC relay connection attempts ordered by lowest
// advertised client-to-relay RTT.
func ExtractWebRTCRelayConnectionInfo(relayData *types.RelayData) ([]WebRTCRelayConnectionInfo, error) {
	if relayData == nil {
		return nil, fmt.Errorf("relay data is nil")
	}
	if len(relayData.Endpoints) == 0 {
		return nil, fmt.Errorf("relay data has no endpoints")
	}
	if len(relayData.RelayKey) == 0 {
		return nil, fmt.Errorf("relay data missing relay key")
	}

	relayKey := base64.StdEncoding.EncodeToString(relayData.RelayKey)
	all := make([]WebRTCRelayConnectionInfo, 0, len(relayData.Endpoints))
	seen := make(map[string]struct{})

	for _, endpoint := range relayData.Endpoints {
		tokenBytes := getRelayAuthTokenBytes(relayData, endpoint)
		if len(tokenBytes) == 0 {
			continue
		}
		// WAWeb uses base64-encoded auth token bytes in SDP ice-ufrag.
		authToken := base64.StdEncoding.EncodeToString(tokenBytes)

		for _, addr := range endpoint.Addresses {
			// WhatsApp may include both protocol=0 and protocol=1 addresses.
			// Keep both so transport can still establish when one protocol set is
			// missing or blocked for the current network.
			if addr.Protocol != 0 && addr.Protocol != 1 {
				continue
			}
			if addr.IPv4 != "" {
				port := addr.Port
				if port == 0 {
					port = defaultRelayPort
				}
				key := fmt.Sprintf("rid=%d|ip=%s|port=%d|auth=%s|relay=%s", endpoint.RelayID, addr.IPv4, port, authToken, relayKey)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				all = append(all, WebRTCRelayConnectionInfo{
					IP:          addr.IPv4,
					Port:        port,
					AuthToken:   authToken,
					RelayKey:    relayKey,
					RelayName:   endpoint.RelayName,
					RelayID:     endpoint.RelayID,
					AuthTokenID: endpoint.AuthTokenID,
					TokenID:     endpoint.TokenID,
					C2RRTTMs:    endpoint.C2RRTTMs,
				})
			}
			if addr.IPv6 != "" {
				port := addr.PortV6
				if port == 0 {
					port = addr.Port
				}
				if port == 0 {
					port = defaultRelayPort
				}
				key := fmt.Sprintf("rid=%d|ip=%s|port=%d|auth=%s|relay=%s", endpoint.RelayID, addr.IPv6, port, authToken, relayKey)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				all = append(all, WebRTCRelayConnectionInfo{
					IP:          addr.IPv6,
					Port:        port,
					AuthToken:   authToken,
					RelayKey:    relayKey,
					RelayName:   endpoint.RelayName,
					RelayID:     endpoint.RelayID,
					AuthTokenID: endpoint.AuthTokenID,
					TokenID:     endpoint.TokenID,
					C2RRTTMs:    endpoint.C2RRTTMs,
				})
			}
		}
	}

	if len(all) == 0 {
		return nil, fmt.Errorf("relay data had no valid protocol 0/1 addresses with credentials")
	}

	sort.SliceStable(all, func(i, j int) bool {
		return relayRTTForSort(all[i].C2RRTTMs) < relayRTTForSort(all[j].C2RRTTMs)
	})

	return all, nil
}

func getRelayAuthTokenBytes(relayData *types.RelayData, endpoint types.RelayEndpoint) []byte {
	if int(endpoint.AuthTokenID) < len(relayData.AuthTokens) {
		auth := relayData.AuthTokens[endpoint.AuthTokenID]
		if len(auth) > 0 {
			return auth
		}
	}
	if int(endpoint.TokenID) < len(relayData.RelayTokens) {
		token := relayData.RelayTokens[endpoint.TokenID]
		if len(token) > 0 {
			return token
		}
	}
	return nil
}

// ExpandWebRTCRelayCredentialVariants returns relay entries with additional
// auth-token/relay-key encoding permutations. This is used as a compatibility
// fallback when relay-side credential format differs from our primary
// extraction assumptions.
func ExpandWebRTCRelayCredentialVariants(relays []WebRTCRelayConnectionInfo) []WebRTCRelayConnectionInfo {
	if len(relays) == 0 {
		return nil
	}
	out := make([]WebRTCRelayConnectionInfo, 0, len(relays)*3)
	seen := make(map[string]struct{}, len(relays)*4)
	for _, relay := range relays {
		authBytes := decodeMaybeBase64OrHexString(relay.AuthToken)
		keyBytes := decodeMaybeBase64OrHexString(relay.RelayKey)

		authHex := strings.ToLower(hex.EncodeToString(authBytes))
		keyHex := strings.ToLower(hex.EncodeToString(keyBytes))
		authB64 := base64.StdEncoding.EncodeToString(authBytes)
		keyB64 := base64.StdEncoding.EncodeToString(keyBytes)
		authRawB64 := base64.RawStdEncoding.EncodeToString(authBytes)
		keyRawB64 := base64.RawStdEncoding.EncodeToString(keyBytes)

		authPrintable := printableASCIIString(authBytes)
		keyPrintable := printableASCIIString(keyBytes)

		candidates := []struct {
			auth string
			key  string
		}{
			// Current primary pair (preserve first).
			{auth: relay.AuthToken, key: relay.RelayKey},
			// Explicit canonical representations.
			{auth: authHex, key: keyB64},
			{auth: authB64, key: keyB64},
			{auth: authRawB64, key: keyRawB64},
			{auth: authHex, key: keyHex},
			{auth: authB64, key: keyHex},
			{auth: authHex, key: relay.RelayKey},
			{auth: relay.AuthToken, key: keyB64},
		}
		if authPrintable != "" && keyPrintable != "" {
			candidates = append(candidates, struct {
				auth string
				key  string
			}{auth: authPrintable, key: keyPrintable})
		}

		for _, candidate := range candidates {
			if candidate.auth == "" || candidate.key == "" {
				continue
			}
			key := fmt.Sprintf(
				"%d|%s|%d|%s|%s",
				relay.RelayID,
				relay.IP,
				relay.Port,
				candidate.auth,
				candidate.key,
			)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			clone := relay
			clone.AuthToken = candidate.auth
			clone.RelayKey = candidate.key
			out = append(out, clone)
			// Keep bounded fanout per relay/address to avoid excessive parallel
			// PeerConnections while still covering common credential variants.
			if len(out) > 0 {
				// Count variants for the current relay/address in insertion order.
				var variantsForCurrent int
				for i := len(out) - 1; i >= 0; i-- {
					if out[i].RelayID == relay.RelayID && out[i].IP == relay.IP && out[i].Port == relay.Port {
						variantsForCurrent++
						continue
					}
					break
				}
				if variantsForCurrent >= 4 {
					break
				}
			}
		}
	}
	if len(out) == 0 {
		return append([]WebRTCRelayConnectionInfo(nil), relays...)
	}
	return out
}

func decodeMaybeBase64OrHexString(input string) []byte {
	if input == "" {
		return nil
	}
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil
	}
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
	return []byte(trimmed)
}

func printableASCIIString(value []byte) string {
	if len(value) == 0 || !utf8.Valid(value) {
		return ""
	}
	for _, b := range value {
		if b < 0x20 || b > 0x7e {
			return ""
		}
	}
	return string(value)
}
