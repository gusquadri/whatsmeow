// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
)

// ParsedCallStanza contains all parsed data from a call stanza.
type ParsedCallStanza struct {
	StanzaID      string
	CallID        string
	CallCreator   types.JID
	From          types.JID
	SignalingType types.SignalingType
	Timestamp     uint64
	IsVideo       bool
	IsOffline     bool
	Platform      string
	Version       string
	GroupJID      types.JID
	CallerPN      types.JID
	CallerUser    string
	Payload       []byte

	Joinable           bool
	CallerCountryCode  string
	Capability         []byte
	Metadata           *types.CallOfferMetadata
	RTE                []byte
	HasUploadFieldStat bool
	VoIPSettings       string
	OfferExtensions    *types.CallOfferExtensions

	OfferEncData  *types.OfferEncData
	EncRekeyData  *types.EncRekeyData
	TransportData *types.TransportPayload
	RelayData     *types.RelayData
	MediaParams   *types.MediaParams
	RelayLatency  []types.RelayLatencyMeasurement
	RelayElection *types.RelayElectionData

	// Raw signaling child node for backward compatibility
	RawNode *waBinary.Node
}

// ParsedOfferAckData contains parsed enrichment data from an outgoing offer ACK.
type ParsedOfferAckData struct {
	RelayData          *types.RelayData
	RTE                []byte
	HasUploadFieldStat bool
	Joinable           bool
	VoIPSettingsByJID  map[types.JID]string
	UserDevices        map[types.JID][]types.JID
}

// ParseCallStanza parses a <call> stanza into a structured representation.
func ParseCallStanza(node *waBinary.Node) (*ParsedCallStanza, error) {
	if node.Tag != "call" {
		return nil, fmt.Errorf("expected 'call' tag, got '%s'", node.Tag)
	}

	children := node.GetChildren()
	if len(children) == 0 {
		return nil, fmt.Errorf("call stanza has no children")
	}

	ag := node.AttrGetter()
	var (
		sigType types.SignalingType
		child   *waBinary.Node
	)
	for i := range children {
		st := types.SignalingTypeFromTag(children[i].Tag)
		if st != types.SignalingNone {
			sigType = st
			child = &children[i]
			break
		}
	}
	if child == nil {
		return nil, fmt.Errorf("call stanza has no signaling type child")
	}
	cag := child.AttrGetter()

	parsed := &ParsedCallStanza{
		StanzaID:      ag.String("id"),
		From:          ag.JID("from"),
		Timestamp:     uint64(ag.UnixTime("t").Unix()),
		IsOffline:     ag.OptionalString("offline") != "",
		Platform:      ag.OptionalString("platform"),
		Version:       ag.OptionalString("version"),
		SignalingType: sigType,
		CallID:        cag.String("call-id"),
		CallCreator:   cag.JID("call-creator"),
		GroupJID:      cag.OptionalJIDOrEmpty("group-jid"),
		CallerPN:      cag.OptionalJIDOrEmpty("caller_pn"),
		CallerUser:    cag.OptionalString("username"),
		RawNode:       child,
	}
	if payload, ok := decodeRawBytes(child.Content); ok {
		parsed.Payload = append([]byte(nil), payload...)
	}

	// Detect video call from <video/> child presence
	for _, c := range child.GetChildren() {
		if c.Tag == "video" {
			parsed.IsVideo = true
			break
		}
	}

	// Parse type-specific data
	switch sigType {
	case types.SignalingOffer:
		parsed.OfferEncData = parseEncData(child)
		parsed.RelayData = parseRelayData(child)
		parsed.MediaParams = parseMediaParams(child)
		parsed.parseOfferExtensions(cag, child)
	case types.SignalingAccept:
		parsed.OfferEncData = parseEncData(child)
		parsed.MediaParams = parseMediaParams(child)
	case types.SignalingRelayLatency:
		parsed.RelayLatency = parseRelayLatency(child)
	case types.SignalingRelayElection:
		parsed.RelayElection = parseRelayElection(child)
	case types.SignalingTransport:
		parsed.TransportData = ParseTransportPayload(parsed.Payload)
	case types.SignalingEncRekey:
		parsed.EncRekeyData = parseEncRekeyData(child)
		if parsed.EncRekeyData != nil {
			parsed.OfferEncData = &types.OfferEncData{
				EncType:    parsed.EncRekeyData.EncType,
				Ciphertext: append([]byte(nil), parsed.EncRekeyData.Ciphertext...),
				Version:    int(parsed.EncRekeyData.Count),
			}
		}
	}

	return parsed, nil
}

func (parsed *ParsedCallStanza) parseOfferExtensions(cag *waBinary.AttrUtility, node *waBinary.Node) {
	parsed.Joinable = cag.OptionalString("joinable") == "1"
	parsed.CallerCountryCode = cag.OptionalString("caller_country_code")

	var privacy []byte
	if privacyNode := node.GetChildByTag("privacy"); privacyNode.Tag != "" {
		if content, ok := decodeHexOrRawBytes(privacyNode.Content); ok {
			privacy = content
		}
	}

	if capabilityNode := node.GetChildByTag("capability"); capabilityNode.Tag != "" {
		if content, ok := decodeHexOrRawBytes(capabilityNode.Content); ok {
			parsed.Capability = content
		}
	}

	if metadataNode := node.GetChildByTag("metadata"); metadataNode.Tag != "" {
		mag := metadataNode.AttrGetter()
		parsed.Metadata = &types.CallOfferMetadata{
			PeerABTestBucket:       mag.OptionalString("peer_abtest_bucket"),
			PeerABTestBucketIDList: mag.OptionalString("peer_abtest_bucket_id_list"),
		}
	}

	if rteNode := node.GetChildByTag("rte"); rteNode.Tag != "" {
		if content, ok := decodeHexOrRawBytes(rteNode.Content); ok {
			parsed.RTE = content
		}
	}

	parsed.HasUploadFieldStat = node.GetChildByTag("uploadfieldstat").Tag != ""

	if voipSettingsNode := node.GetChildByTag("voip_settings"); voipSettingsNode.Tag != "" {
		if content, ok := decodeRawBytes(voipSettingsNode.Content); ok {
			parsed.VoIPSettings = string(content)
		}
	}

	if len(privacy) > 0 || parsed.Joinable || parsed.CallerCountryCode != "" || len(parsed.Capability) > 0 || parsed.Metadata != nil || len(parsed.RTE) > 0 || parsed.HasUploadFieldStat || parsed.VoIPSettings != "" {
		parsed.OfferExtensions = &types.CallOfferExtensions{
			Joinable:          parsed.Joinable,
			CallerCountryCode: parsed.CallerCountryCode,
			Privacy:           append([]byte(nil), privacy...),
			Capability:        append([]byte(nil), parsed.Capability...),
			Metadata:          parsed.Metadata,
			RTE:               append([]byte(nil), parsed.RTE...),
			UploadFieldStat:   parsed.HasUploadFieldStat,
			VoIPSettings:      parsed.VoIPSettings,
		}
	}
}

func parseRelayData(node *waBinary.Node) *types.RelayData {
	relay := node.GetChildByTag("relay")
	if relay.Tag == "" {
		return nil
	}

	rag := relay.AttrGetter()
	data := &types.RelayData{
		AttributePadding: rag.OptionalString("attribute_padding") == "1",
		UUID:             rag.OptionalString("uuid"),
		SelfPID:          parseUint32Attr(rag, "self_pid"),
		PeerPID:          parseUint32Attr(rag, "peer_pid"),
	}

	// Parse hbh_key
	if hbhNode := relay.GetChildByTag("hbh_key"); hbhNode.Tag != "" {
		if content, ok := decodeBase64OrRawBytes(hbhNode.Content); ok {
			data.HBHKey = content
		}
	}

	// Parse relay key
	if keyNode := relay.GetChildByTag("key"); keyNode.Tag != "" {
		if content, ok := decodeBase64OrRawBytes(keyNode.Content); ok {
			data.RelayKey = content
		}
	}

	// Parse tokens
	data.RelayTokens = parseIndexedTokens(&relay, "token")
	data.AuthTokens = parseIndexedTokens(&relay, "auth_token")

	// Parse participants
	for _, participant := range relay.GetChildrenByTag("participant") {
		pag := participant.AttrGetter()
		jid := pag.OptionalJIDOrEmpty("jid")
		if jid.IsEmpty() {
			continue
		}
		data.Participants = append(data.Participants, types.RelayParticipant{
			JID: jid,
			PID: parseUint32Attr(pag, "pid"),
		})
	}

	// Parse te2 endpoints.
	// Some offer-ack payloads include multiple te2 entries for the same relay_id
	// (e.g. protocol variants / IPv4+IPv6). Merge those into one endpoint with
	// multiple addresses to avoid duplicated downstream relay latency signaling.
	type relayEndpointKey struct {
		relayID     uint32
		relayName   string
		tokenID     uint32
		authTokenID uint32
	}
	endpointIndex := make(map[relayEndpointKey]int)
	for _, te2 := range relay.GetChildrenByTag("te2") {
		te2ag := te2.AttrGetter()
		endpoint := types.RelayEndpoint{
			RelayID:     parseUint32Attr(te2ag, "relay_id"),
			RelayName:   te2ag.OptionalString("relay_name"),
			TokenID:     parseUint32Attr(te2ag, "token_id"),
			AuthTokenID: parseUint32Attr(te2ag, "auth_token_id"),
		}
		key := relayEndpointKey{
			relayID:     endpoint.RelayID,
			relayName:   endpoint.RelayName,
			tokenID:     endpoint.TokenID,
			authTokenID: endpoint.AuthTokenID,
		}
		index, exists := endpointIndex[key]
		if !exists {
			data.Endpoints = append(data.Endpoints, endpoint)
			index = len(data.Endpoints) - 1
			endpointIndex[key] = index
		}
		if c2rRTT, ok := parseOptionalUint32Attr(te2ag, "c2r_rtt"); ok {
			existing := data.Endpoints[index]
			if existing.C2RRTTMs == nil || c2rRTT < *existing.C2RRTTMs {
				rtt := c2rRTT
				existing.C2RRTTMs = &rtt
				data.Endpoints[index] = existing
			}
		}
		protocol := uint8(parseUint32Attr(te2ag, "protocol"))

		if content, ok := te2.Content.([]byte); ok {
			if addr := parseTe2Address(content, protocol); addr != nil {
				existing := data.Endpoints[index]
				if !relayAddressExists(existing.Addresses, *addr) {
					existing.Addresses = append(existing.Addresses, *addr)
					data.Endpoints[index] = existing
				}
			}
		}
	}

	return data
}

func relayAddressExists(addresses []types.RelayAddress, candidate types.RelayAddress) bool {
	for _, addr := range addresses {
		if addr == candidate {
			return true
		}
	}
	return false
}

func parseIndexedTokens(node *waBinary.Node, tag string) [][]byte {
	var tokens [][]byte
	for _, child := range node.GetChildrenByTag(tag) {
		if content, ok := decodeHexOrRawBytes(child.Content); ok {
			ag := child.AttrGetter()
			idStr := ag.OptionalString("id")
			id := 0
			if idStr != "" {
				if parsed, err := strconv.Atoi(idStr); err == nil {
					id = parsed
				}
			} else {
				id = len(tokens)
			}
			for len(tokens) <= id {
				tokens = append(tokens, nil)
			}
			tokens[id] = content
		}
	}
	return tokens
}

func parseTe2Address(data []byte, protocol uint8) *types.RelayAddress {
	switch len(data) {
	case 6:
		// IPv4: 4 bytes IP + 2 bytes port big-endian
		ip := fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3])
		port := binary.BigEndian.Uint16(data[4:6])
		return &types.RelayAddress{
			IPv4:     ip,
			Port:     port,
			Protocol: protocol,
		}
	case 18:
		// IPv6: 16 bytes IP + 2 bytes port big-endian
		ipv6 := net.IP(data[:16]).String()
		port := binary.BigEndian.Uint16(data[16:18])
		return &types.RelayAddress{
			IPv6:     ipv6,
			Port:     port,
			PortV6:   port,
			Protocol: protocol,
		}
	}
	return nil
}

func parseMediaParams(node *waBinary.Node) *types.MediaParams {
	params := &types.MediaParams{}
	for _, child := range node.GetChildren() {
		switch child.Tag {
		case "audio":
			ag := child.AttrGetter()
			codec := ag.OptionalString("enc")
			if codec == "" {
				codec = "opus"
			}
			rateStr := ag.OptionalString("rate")
			rate := uint32(16000)
			if rateStr != "" {
				if parsed, err := strconv.ParseUint(rateStr, 10, 32); err == nil {
					rate = uint32(parsed)
				}
			}
			params.Audio = append(params.Audio, types.AudioParams{Codec: codec, Rate: rate})
		case "video":
			ag := child.AttrGetter()
			codec := ag.OptionalString("enc")
			params.Video = &types.VideoParams{Codec: codec}
		}
	}
	if len(params.Audio) == 0 && params.Video == nil {
		return nil
	}
	return params
}

func parseRelayLatency(node *waBinary.Node) []types.RelayLatencyMeasurement {
	var measurements []types.RelayLatencyMeasurement
	for _, child := range node.GetChildrenByTag("te") {
		ag := child.AttrGetter()
		relayName := ag.OptionalString("relay_name")
		latencyStr := ag.OptionalString("latency")
		rawLatency := uint32(0)
		if latencyStr != "" {
			if parsed, err := strconv.ParseUint(latencyStr, 10, 32); err == nil {
				rawLatency = uint32(parsed)
			}
		}
		latency := types.RelayLatencyMeasurement{
			RelayID:    parseUint32Attr(ag, "relay_id"),
			RelayName:  relayName,
			LatencyMs:  rawLatency & 0x00FFFFFF,
			RawLatency: rawLatency,
		}
		if addr, ok := decodeRawBytes(child.Content); ok {
			switch len(addr) {
			case 6:
				latency.IPv4 = fmt.Sprintf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3])
				latency.Port = binary.BigEndian.Uint16(addr[4:6])
			case 18:
				latency.IPv6 = net.IP(addr[:16]).String()
				latency.Port = binary.BigEndian.Uint16(addr[16:18])
			}
		}
		measurements = append(measurements, latency)
	}
	return measurements
}

func parseRelayElection(node *waBinary.Node) *types.RelayElectionData {
	ag := node.AttrGetter()

	// Try attribute first
	if idxStr := ag.OptionalString("elected_relay_idx"); idxStr != "" {
		if idx, err := strconv.ParseUint(idxStr, 10, 32); err == nil {
			return &types.RelayElectionData{ElectedRelayIndex: uint32(idx)}
		}
	}
	if idxStr := ag.OptionalString("relay_id"); idxStr != "" {
		if idx, err := strconv.ParseUint(idxStr, 10, 32); err == nil {
			return &types.RelayElectionData{ElectedRelayIndex: uint32(idx)}
		}
	}

	// Try binary payload
	if content, ok := node.Content.([]byte); ok {
		if len(content) >= 4 {
			idx := binary.BigEndian.Uint32(content[:4])
			return &types.RelayElectionData{ElectedRelayIndex: idx}
		} else if len(content) > 0 {
			var idx uint32
			for _, b := range content {
				idx = (idx << 8) | uint32(b)
			}
			return &types.RelayElectionData{ElectedRelayIndex: idx}
		}
	}

	return nil
}

func parseEncRekeyData(node *waBinary.Node) *types.EncRekeyData {
	enc := node.GetChildByTag("enc")
	if enc.Tag == "" {
		return nil
	}
	ag := enc.AttrGetter()
	content, ok := decodeBase64OrRawBytes(enc.Content)
	if !ok {
		return nil
	}
	count := uint32(1)
	if parsed, ok := parseOptionalUint32Attr(ag, "count"); ok {
		count = parsed
	}
	return &types.EncRekeyData{
		EncType:    ag.String("type"),
		Ciphertext: content,
		Count:      count,
	}
}

func parseUint32Attr(ag *waBinary.AttrUtility, key string) uint32 {
	s := ag.OptionalString(key)
	if s == "" {
		return 0
	}
	v, _ := strconv.ParseUint(s, 10, 32)
	return uint32(v)
}

func parseOptionalUint32Attr(ag *waBinary.AttrUtility, key string) (uint32, bool) {
	s := ag.OptionalString(key)
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

// ParseRelayDataFromCallAck parses relay allocation data from an offer ACK node.
func ParseRelayDataFromCallAck(node *waBinary.Node) *types.RelayData {
	ack := ParseOfferAckData(node)
	if ack == nil {
		return nil
	}
	return ack.RelayData
}

// ParseOfferAckData parses enrichment data from an offer ACK node.
func ParseOfferAckData(node *waBinary.Node) *ParsedOfferAckData {
	if node == nil || node.Tag != "ack" {
		return nil
	}
	ag := node.AttrGetter()
	if ag.OptionalString("class") != "call" {
		return nil
	}
	if ag.OptionalString("type") != types.SignalingOffer.Tag() {
		return nil
	}

	parsed := &ParsedOfferAckData{
		RelayData:          parseRelayData(node),
		HasUploadFieldStat: node.GetChildByTag("uploadfieldstat").Tag != "",
		VoIPSettingsByJID:  make(map[types.JID]string),
		UserDevices:        make(map[types.JID][]types.JID),
	}

	if rteNode := node.GetChildByTag("rte"); rteNode.Tag != "" {
		if content, ok := decodeHexOrRawBytes(rteNode.Content); ok {
			parsed.RTE = content
		}
	}

	if relayNode := node.GetChildByTag("relay"); relayNode.Tag != "" {
		rag := relayNode.AttrGetter()
		parsed.Joinable = rag.OptionalString("joinable") == "1"
	}

	for _, child := range node.GetChildrenByTag("voip_settings") {
		ag := child.AttrGetter()
		jid := ag.OptionalJIDOrEmpty("jid")
		if jid.IsEmpty() {
			continue
		}
		if content, ok := decodeRawBytes(child.Content); ok {
			parsed.VoIPSettingsByJID[jid.ToNonAD()] = string(content)
		}
	}

	for _, userNode := range node.GetChildrenByTag("user") {
		uag := userNode.AttrGetter()
		userJID := uag.OptionalJIDOrEmpty("jid")
		if userJID.IsEmpty() {
			continue
		}
		userJID = userJID.ToNonAD()
		for _, deviceNode := range userNode.GetChildrenByTag("device") {
			dag := deviceNode.AttrGetter()
			deviceJID := dag.OptionalJIDOrEmpty("jid")
			if deviceJID.IsEmpty() {
				continue
			}
			parsed.UserDevices[userJID] = append(parsed.UserDevices[userJID], deviceJID.ToNonAD())
		}
	}

	if len(parsed.VoIPSettingsByJID) == 0 {
		parsed.VoIPSettingsByJID = nil
	}
	if len(parsed.UserDevices) == 0 {
		parsed.UserDevices = nil
	}

	return parsed
}

func decodeRawBytes(content interface{}) ([]byte, bool) {
	switch v := content.(type) {
	case []byte:
		return v, true
	case string:
		return []byte(v), true
	default:
		return nil, false
	}
}

func decodeHexOrRawBytes(content interface{}) ([]byte, bool) {
	switch v := content.(type) {
	case string:
		trimmed := strings.TrimSpace(v)
		if len(trimmed) >= 2 && trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"' {
			trimmed = trimmed[1 : len(trimmed)-1]
		}
		if isHexString(trimmed) && len(trimmed)%2 == 0 {
			decoded, err := hex.DecodeString(trimmed)
			if err == nil {
				return decoded, true
			}
		}
		return []byte(v), true
	case []byte:
		copied := make([]byte, len(v))
		copy(copied, v)
		return copied, true
	default:
		return nil, false
	}
}

func isHexString(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') {
			continue
		}
		return false
	}
	return true
}

func decodeBase64OrRawBytes(content interface{}) ([]byte, bool) {
	switch v := content.(type) {
	case string:
		candidates := []string{strings.TrimSpace(v)}
		trimmed := candidates[0]
		if len(trimmed) >= 2 && trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"' {
			candidates = append([]string{trimmed[1 : len(trimmed)-1]}, candidates...)
		}
		for _, candidate := range candidates {
			decoded, err := base64.StdEncoding.DecodeString(candidate)
			if err == nil {
				return decoded, true
			}
		}
		return []byte(v), true
	case []byte:
		// Preserve binary payloads as-is. Some relay payloads can be arbitrary
		// bytes that may coincidentally form valid base64 text.
		copied := make([]byte, len(v))
		copy(copied, v)
		return copied, true
	default:
		return nil, false
	}
}

// Capability bytes from WhatsApp Web logs
var defaultCapability = []byte{0x01, 0x05, 0xF7, 0x09, 0xE4, 0xBB, 0x13}

// BuildOfferStanza builds a <call><offer> stanza for initiating a call.
func (cli *Client) BuildOfferStanza(info *types.CallInfo, encCiphertext []byte, encType string, includeDeviceIdentity bool) waBinary.Node {
	offerExt := info.OfferExtensions
	if offerExt == nil {
		offerExt = &types.CallOfferExtensions{}
	}

	capability := defaultCapability
	if len(offerExt.Capability) > 0 {
		capability = offerExt.Capability
	}

	children := []waBinary.Node{}
	if len(offerExt.Privacy) > 0 {
		children = append(children, waBinary.Node{
			Tag:     "privacy",
			Content: strings.ToUpper(hex.EncodeToString(offerExt.Privacy)),
		})
	}
	children = append(children,
		waBinary.Node{Tag: "audio", Attrs: waBinary.Attrs{"enc": "opus", "rate": "8000"}},
		waBinary.Node{Tag: "audio", Attrs: waBinary.Attrs{"enc": "opus", "rate": "16000"}},
		waBinary.Node{Tag: "net", Attrs: waBinary.Attrs{"medium": "3"}},
		waBinary.Node{Tag: "capability", Attrs: waBinary.Attrs{"ver": "1"}, Content: capability},
		waBinary.Node{Tag: "enc", Attrs: waBinary.Attrs{"type": encType, "v": "2"}, Content: encCiphertext},
		waBinary.Node{Tag: "encopt", Attrs: waBinary.Attrs{"keygen": "2"}},
	)

	if includeDeviceIdentity {
		children = append(children, cli.makeDeviceIdentityNode())
	}
	children = append(children, buildOptionalOfferChildren(offerExt, info.RelayData)...)

	if info.IsVideo {
		children = append(children, waBinary.Node{Tag: "video"})
	}

	offerAttrs := waBinary.Attrs{
		"call-id":      info.CallID,
		"call-creator": info.CallCreator,
	}
	if offerExt.Joinable {
		offerAttrs["joinable"] = "1"
	}
	if offerExt.CallerCountryCode != "" {
		offerAttrs["caller_country_code"] = offerExt.CallerCountryCode
	}
	if !info.GroupJID.IsEmpty() {
		offerAttrs["group-jid"] = info.GroupJID
	}
	if !info.CallerPN.IsEmpty() && info.CallerPN.Server == types.DefaultUserServer {
		offerAttrs["caller_pn"] = info.CallerPN
	}

	return waBinary.Node{
		Tag:   "call",
		Attrs: waBinary.Attrs{"id": cli.GenerateMessageID(), "to": info.PeerJID},
		Content: []waBinary.Node{{
			Tag:     "offer",
			Attrs:   offerAttrs,
			Content: children,
		}},
	}
}

// BuildOfferStanzaWithDestinations builds a WAWeb-style offer where encrypted
// call-key material is faned out per destination device under <destination>.
func (cli *Client) BuildOfferStanzaWithDestinations(info *types.CallInfo, encTargets []CallOfferEncryptedTarget, includeDeviceIdentity bool) waBinary.Node {
	if len(encTargets) == 0 {
		return cli.BuildOfferStanza(info, nil, "msg", includeDeviceIdentity)
	}

	offerExt := info.OfferExtensions
	if offerExt == nil {
		offerExt = &types.CallOfferExtensions{}
	}

	capability := defaultCapability
	if len(offerExt.Capability) > 0 {
		capability = offerExt.Capability
	}

	destinationChildren := make([]waBinary.Node, 0, len(encTargets))
	for _, target := range encTargets {
		if target.JID.IsEmpty() || len(target.Ciphertext) == 0 {
			continue
		}
		encType := target.EncType
		if encType == "" {
			encType = "msg"
		}
		destinationChildren = append(destinationChildren, waBinary.Node{
			Tag:   "to",
			Attrs: waBinary.Attrs{"jid": target.JID},
			Content: []waBinary.Node{{
				Tag: "enc",
				Attrs: waBinary.Attrs{
					"type":  encType,
					"v":     "2",
					"count": strconv.FormatUint(uint64(target.Count), 10),
				},
				Content: target.Ciphertext,
			}},
		})
	}

	children := []waBinary.Node{}
	if len(offerExt.Privacy) > 0 {
		children = append(children, waBinary.Node{
			Tag:     "privacy",
			Content: strings.ToUpper(hex.EncodeToString(offerExt.Privacy)),
		})
	}
	children = append(children,
		waBinary.Node{Tag: "audio", Attrs: waBinary.Attrs{"enc": "opus", "rate": "8000"}},
		waBinary.Node{Tag: "audio", Attrs: waBinary.Attrs{"enc": "opus", "rate": "16000"}},
		waBinary.Node{Tag: "net", Attrs: waBinary.Attrs{"medium": "3"}},
		waBinary.Node{Tag: "capability", Attrs: waBinary.Attrs{"ver": "1"}, Content: capability},
	)
	if len(destinationChildren) > 0 {
		children = append(children, waBinary.Node{Tag: "destination", Content: destinationChildren})
	}
	children = append(children, waBinary.Node{Tag: "encopt", Attrs: waBinary.Attrs{"keygen": "2"}})

	if includeDeviceIdentity {
		children = append(children, cli.makeDeviceIdentityNode())
	}
	children = append(children, buildOptionalOfferChildren(offerExt, info.RelayData)...)

	if info.IsVideo {
		children = append(children, waBinary.Node{Tag: "video"})
	}

	offerAttrs := waBinary.Attrs{
		"call-id":      info.CallID,
		"call-creator": info.CallCreator,
	}
	if offerExt.Joinable {
		offerAttrs["joinable"] = "1"
	}
	if offerExt.CallerCountryCode != "" {
		offerAttrs["caller_country_code"] = offerExt.CallerCountryCode
	}
	if !info.GroupJID.IsEmpty() {
		offerAttrs["group-jid"] = info.GroupJID
	}
	if !info.CallerPN.IsEmpty() && info.CallerPN.Server == types.DefaultUserServer {
		offerAttrs["caller_pn"] = info.CallerPN
	}

	return waBinary.Node{
		Tag:   "call",
		Attrs: waBinary.Attrs{"id": cli.GenerateMessageID(), "to": info.PeerJID},
		Content: []waBinary.Node{{
			Tag:     "offer",
			Attrs:   offerAttrs,
			Content: children,
		}},
	}
}

func buildOptionalOfferChildren(offerExt *types.CallOfferExtensions, relayData *types.RelayData) []waBinary.Node {
	var children []waBinary.Node
	if offerExt == nil {
		offerExt = &types.CallOfferExtensions{}
	}
	if offerExt.Metadata != nil && (offerExt.Metadata.PeerABTestBucket != "" || offerExt.Metadata.PeerABTestBucketIDList != "") {
		children = append(children, waBinary.Node{
			Tag: "metadata",
			Attrs: waBinary.Attrs{
				"peer_abtest_bucket":         offerExt.Metadata.PeerABTestBucket,
				"peer_abtest_bucket_id_list": offerExt.Metadata.PeerABTestBucketIDList,
			},
		})
	}
	if len(offerExt.RTE) > 0 {
		children = append(children, waBinary.Node{Tag: "rte", Content: offerExt.RTE})
	}
	if offerExt.UploadFieldStat {
		children = append(children, waBinary.Node{Tag: "uploadfieldstat"})
	}
	if offerExt.VoIPSettings != "" {
		children = append(children, waBinary.Node{
			Tag:     "voip_settings",
			Attrs:   waBinary.Attrs{"uncompressed": "1"},
			Content: offerExt.VoIPSettings,
		})
	}
	if relayNode, ok := buildOfferRelayNode(relayData); ok {
		children = append(children, relayNode)
	}
	return children
}

func buildOfferRelayNode(data *types.RelayData) (waBinary.Node, bool) {
	if data == nil {
		return waBinary.Node{}, false
	}
	relayAttrs := waBinary.Attrs{}
	if data.UUID != "" {
		relayAttrs["uuid"] = data.UUID
	}
	if data.SelfPID > 0 {
		relayAttrs["self_pid"] = strconv.FormatUint(uint64(data.SelfPID), 10)
	}
	if data.PeerPID > 0 {
		relayAttrs["peer_pid"] = strconv.FormatUint(uint64(data.PeerPID), 10)
	}
	if data.AttributePadding {
		relayAttrs["attribute_padding"] = "1"
	}

	var relayChildren []waBinary.Node
	for _, participant := range data.Participants {
		if participant.JID.IsEmpty() {
			continue
		}
		participantAttrs := waBinary.Attrs{"jid": participant.JID}
		if participant.PID > 0 {
			participantAttrs["pid"] = strconv.FormatUint(uint64(participant.PID), 10)
		}
		relayChildren = append(relayChildren, waBinary.Node{Tag: "participant", Attrs: participantAttrs})
	}
	for idx, token := range data.RelayTokens {
		if len(token) == 0 {
			continue
		}
		relayChildren = append(relayChildren, waBinary.Node{
			Tag:     "token",
			Attrs:   waBinary.Attrs{"id": strconv.Itoa(idx)},
			Content: append([]byte(nil), token...),
		})
	}
	for idx, token := range data.AuthTokens {
		if len(token) == 0 {
			continue
		}
		relayChildren = append(relayChildren, waBinary.Node{
			Tag:     "auth_token",
			Attrs:   waBinary.Attrs{"id": strconv.Itoa(idx)},
			Content: hex.EncodeToString(token),
		})
	}
	if len(data.RelayKey) > 0 {
		relayChildren = append(relayChildren, waBinary.Node{
			Tag:     "key",
			Content: base64.StdEncoding.EncodeToString(data.RelayKey),
		})
	}
	if len(data.HBHKey) > 0 {
		relayChildren = append(relayChildren, waBinary.Node{
			Tag:     "hbh_key",
			Content: base64.StdEncoding.EncodeToString(data.HBHKey),
		})
	}
	for _, endpoint := range data.Endpoints {
		te2Attrs := waBinary.Attrs{
			"relay_id":      strconv.FormatUint(uint64(endpoint.RelayID), 10),
			"token_id":      strconv.FormatUint(uint64(endpoint.TokenID), 10),
			"auth_token_id": strconv.FormatUint(uint64(endpoint.AuthTokenID), 10),
		}
		if endpoint.RelayName != "" {
			te2Attrs["relay_name"] = endpoint.RelayName
		}
		if endpoint.C2RRTTMs != nil {
			te2Attrs["c2r_rtt"] = strconv.FormatUint(uint64(*endpoint.C2RRTTMs), 10)
		}
		if len(endpoint.Addresses) == 0 {
			relayChildren = append(relayChildren, waBinary.Node{Tag: "te2", Attrs: te2Attrs})
			continue
		}
		for _, addr := range endpoint.Addresses {
			nodeAttrs := make(waBinary.Attrs, len(te2Attrs)+1)
			for key, value := range te2Attrs {
				nodeAttrs[key] = value
			}
			if addr.Protocol > 0 {
				nodeAttrs["protocol"] = strconv.FormatUint(uint64(addr.Protocol), 10)
			}
			content, ok := encodeRelayAddress(addr)
			if !ok {
				relayChildren = append(relayChildren, waBinary.Node{Tag: "te2", Attrs: nodeAttrs})
				continue
			}
			relayChildren = append(relayChildren, waBinary.Node{Tag: "te2", Attrs: nodeAttrs, Content: content})
		}
	}

	return waBinary.Node{Tag: "relay", Attrs: relayAttrs, Content: relayChildren}, true
}

func encodeRelayAddress(addr types.RelayAddress) ([]byte, bool) {
	port := addr.Port
	if port == 0 {
		port = addr.PortV6
	}
	if port == 0 {
		port = defaultRelayPort
	}
	if addr.IPv4 != "" {
		ip := net.ParseIP(addr.IPv4).To4()
		if ip == nil {
			return nil, false
		}
		out := make([]byte, 6)
		copy(out[:4], ip)
		binary.BigEndian.PutUint16(out[4:], port)
		return out, true
	}
	if addr.IPv6 != "" {
		ip := net.ParseIP(addr.IPv6).To16()
		if ip == nil {
			return nil, false
		}
		out := make([]byte, 18)
		copy(out[:16], ip)
		binary.BigEndian.PutUint16(out[16:], port)
		return out, true
	}
	return nil, false
}

func buildCallDestinationNode(info *types.CallInfo) (waBinary.Node, bool) {
	if info == nil {
		return waBinary.Node{}, false
	}
	destinations := collectCallDestinationJIDs(info)
	if len(destinations) == 0 {
		return waBinary.Node{}, false
	}
	children := make([]waBinary.Node, 0, len(destinations))
	for _, jid := range destinations {
		children = append(children, waBinary.Node{
			Tag:   "to",
			Attrs: waBinary.Attrs{"jid": jid},
		})
	}
	return waBinary.Node{Tag: "destination", Content: children}, true
}

func collectCallDestinationJIDs(info *types.CallInfo) []types.JID {
	if info == nil {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]types.JID, 0, 4)
	add := func(jid types.JID) {
		jid = jid.ToNonAD()
		if jid.IsEmpty() {
			return
		}
		key := jid.String()
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		out = append(out, jid)
	}

	for _, devices := range info.OfferAckDevices {
		for _, deviceJID := range devices {
			add(deviceJID)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].String() < out[j].String()
	})
	return out
}

// BuildAcceptStanza builds a <call><accept> stanza for accepting an incoming call.
func (cli *Client) BuildAcceptStanza(info *types.CallInfo) waBinary.Node {
	children := []waBinary.Node{
		{Tag: "audio", Attrs: waBinary.Attrs{"enc": "opus", "rate": "16000"}},
		{Tag: "net", Attrs: waBinary.Attrs{"medium": "2"}},
		{Tag: "encopt", Attrs: waBinary.Attrs{"keygen": "2"}},
	}

	if info.IsVideo {
		children = append(children, waBinary.Node{Tag: "video", Attrs: waBinary.Attrs{"enc": "vp8"}})
	}

	return waBinary.Node{
		Tag:   "call",
		Attrs: waBinary.Attrs{"id": cli.GenerateMessageID(), "to": info.PeerJID},
		Content: []waBinary.Node{{
			Tag:     "accept",
			Attrs:   waBinary.Attrs{"call-id": info.CallID, "call-creator": info.CallCreator, "count": "0"},
			Content: children,
		}},
	}
}

// BuildPreAcceptStanza builds a <call><preaccept> stanza to signal ringing state.
func (cli *Client) BuildPreAcceptStanza(info *types.CallInfo) waBinary.Node {
	return waBinary.Node{
		Tag:   "call",
		Attrs: waBinary.Attrs{"id": cli.GenerateMessageID(), "to": info.PeerJID},
		Content: []waBinary.Node{{
			Tag:   "preaccept",
			Attrs: waBinary.Attrs{"call-id": info.CallID, "call-creator": info.CallCreator, "count": "0"},
			Content: []waBinary.Node{
				{Tag: "audio", Attrs: waBinary.Attrs{"enc": "opus", "rate": "16000"}},
				{Tag: "encopt", Attrs: waBinary.Attrs{"keygen": "2"}},
				{Tag: "capability", Attrs: waBinary.Attrs{"ver": "1"}, Content: defaultCapability},
			},
		}},
	}
}

// BuildTerminateStanza builds a <call><terminate> stanza to end a call.
func (cli *Client) BuildTerminateStanza(info *types.CallInfo) waBinary.Node {
	terminateChildren := []waBinary.Node{}
	if destination, ok := buildCallDestinationNode(info); ok {
		terminateChildren = append(terminateChildren, destination)
	}
	return waBinary.Node{
		Tag:   "call",
		Attrs: waBinary.Attrs{"id": cli.GenerateMessageID(), "to": info.PeerJID},
		Content: []waBinary.Node{{
			Tag:     "terminate",
			Attrs:   waBinary.Attrs{"call-id": info.CallID, "call-creator": info.CallCreator, "count": "0"},
			Content: terminateChildren,
		}},
	}
}

// BuildRejectStanza builds a <call><reject> stanza to reject a call.
func (cli *Client) BuildRejectStanza(info *types.CallInfo) waBinary.Node {
	return waBinary.Node{
		Tag:   "call",
		Attrs: waBinary.Attrs{"id": cli.GenerateMessageID(), "to": info.PeerJID},
		Content: []waBinary.Node{{
			Tag:   "reject",
			Attrs: waBinary.Attrs{"call-id": info.CallID, "call-creator": info.CallCreator, "count": "0"},
		}},
	}
}

// BuildRelayLatencyStanzas builds one <call><relaylatency> stanza per relay
// endpoint, matching WAWeb's behavior of sending individual measurements.
func (cli *Client) BuildRelayLatencyStanzas(info *types.CallInfo, relayData *types.RelayData) []waBinary.Node {
	const defaultRelayLatencyMs = uint32(50)
	var destination waBinary.Node
	hasDestination := false
	if d, ok := buildCallDestinationNode(info); ok {
		destination = d
		hasDestination = true
	}

	// Merge duplicate relay endpoint variants (same relay tuple) to avoid
	// emitting duplicated relaylatency stanzas for protocol/address variants.
	type relayLatencyKey struct {
		relayID     uint32
		relayName   string
		tokenID     uint32
		authTokenID uint32
	}
	endpointByKey := make(map[relayLatencyKey]int)
	mergedEndpoints := make([]types.RelayEndpoint, 0, len(relayData.Endpoints))
	for _, endpoint := range relayData.Endpoints {
		key := relayLatencyKey{
			relayID:     endpoint.RelayID,
			relayName:   endpoint.RelayName,
			tokenID:     endpoint.TokenID,
			authTokenID: endpoint.AuthTokenID,
		}
		index, exists := endpointByKey[key]
		if !exists {
			copied := endpoint
			if len(endpoint.Addresses) > 0 {
				copied.Addresses = append([]types.RelayAddress(nil), endpoint.Addresses...)
			}
			if endpoint.C2RRTTMs != nil {
				rtt := *endpoint.C2RRTTMs
				copied.C2RRTTMs = &rtt
			}
			mergedEndpoints = append(mergedEndpoints, copied)
			endpointByKey[key] = len(mergedEndpoints) - 1
			continue
		}
		existing := mergedEndpoints[index]
		if existing.C2RRTTMs == nil || (endpoint.C2RRTTMs != nil && *endpoint.C2RRTTMs < *existing.C2RRTTMs) {
			if endpoint.C2RRTTMs != nil {
				rtt := *endpoint.C2RRTTMs
				existing.C2RRTTMs = &rtt
			}
		}
		if existing.RelayName == "" && endpoint.RelayName != "" {
			existing.RelayName = endpoint.RelayName
		}
		for _, addr := range endpoint.Addresses {
			if !relayAddressExists(existing.Addresses, addr) {
				existing.Addresses = append(existing.Addresses, addr)
			}
		}
		mergedEndpoints[index] = existing
	}

	var stanzas []waBinary.Node
	for _, endpoint := range mergedEndpoints {
		latencyMs := defaultRelayLatencyMs
		if endpoint.C2RRTTMs != nil {
			latencyMs = *endpoint.C2RRTTMs
		}
		encodedLatency := 0x2000000 + latencyMs

		addrBytes := buildRelayLatencyAddressBytes(endpoint.Addresses)

		teAttrs := waBinary.Attrs{
			"latency":    strconv.FormatUint(uint64(encodedLatency), 10),
			"relay_name": endpoint.RelayName,
		}

		teNode := waBinary.Node{Tag: "te", Attrs: teAttrs}
		if addrBytes != nil {
			teNode.Content = addrBytes
		}

		children := []waBinary.Node{teNode}
		if hasDestination {
			children = append(children, destination)
		}

		stanzas = append(stanzas, waBinary.Node{
			Tag:   "call",
			Attrs: waBinary.Attrs{"id": cli.GenerateMessageID(), "to": info.PeerJID},
			Content: []waBinary.Node{{
				Tag:     "relaylatency",
				Attrs:   waBinary.Attrs{"call-id": info.CallID, "call-creator": info.CallCreator, "count": "0"},
				Content: children,
			}},
		})
	}
	return stanzas
}

func buildRelayLatencyAddressBytes(addresses []types.RelayAddress) []byte {
	encodeIPv4 := func(addr types.RelayAddress) []byte {
		if addr.IPv4 == "" {
			return nil
		}
		ip := net.ParseIP(addr.IPv4).To4()
		if ip == nil {
			return nil
		}
		port := addr.Port
		if port == 0 {
			port = defaultRelayPort
		}
		out := make([]byte, 6)
		copy(out, ip)
		binary.BigEndian.PutUint16(out[4:], port)
		return out
	}
	encodeIPv6 := func(addr types.RelayAddress) []byte {
		if addr.IPv6 == "" {
			return nil
		}
		ip := net.ParseIP(addr.IPv6).To16()
		if ip == nil {
			return nil
		}
		port := addr.PortV6
		if port == 0 {
			port = addr.Port
		}
		if port == 0 {
			port = defaultRelayPort
		}
		out := make([]byte, 18)
		copy(out, ip)
		binary.BigEndian.PutUint16(out[16:], port)
		return out
	}
	for _, addr := range addresses {
		if addr.Protocol == 0 {
			if out := encodeIPv4(addr); out != nil {
				return out
			}
		}
	}
	for _, addr := range addresses {
		if addr.Protocol == 1 {
			if out := encodeIPv4(addr); out != nil {
				return out
			}
		}
	}
	for _, addr := range addresses {
		if out := encodeIPv4(addr); out != nil {
			return out
		}
	}
	for _, addr := range addresses {
		if addr.Protocol == 0 {
			if out := encodeIPv6(addr); out != nil {
				return out
			}
		}
	}
	for _, addr := range addresses {
		if addr.Protocol == 1 {
			if out := encodeIPv6(addr); out != nil {
				return out
			}
		}
	}
	for _, addr := range addresses {
		if out := encodeIPv6(addr); out != nil {
			return out
		}
	}
	return nil
}

// BuildRelayLatencyStanza builds a single <call><relaylatency> stanza with all
// measurements. Deprecated: use BuildRelayLatencyStanzas for WAWeb-compatible
// per-relay stanzas.
func (cli *Client) BuildRelayLatencyStanza(info *types.CallInfo, relayData *types.RelayData) waBinary.Node {
	stanzas := cli.BuildRelayLatencyStanzas(info, relayData)
	if len(stanzas) == 1 {
		return stanzas[0]
	}
	// Fallback: merge all te nodes into a single stanza for backward compat.
	var children []waBinary.Node
	for _, s := range stanzas {
		if callContent, ok := s.Content.([]waBinary.Node); ok && len(callContent) > 0 {
			if rlContent, ok := callContent[0].Content.([]waBinary.Node); ok {
				for _, child := range rlContent {
					if child.Tag == "te" {
						children = append(children, child)
					}
				}
			}
		}
	}
	if destination, ok := buildCallDestinationNode(info); ok {
		children = append(children, destination)
	}
	return waBinary.Node{
		Tag:   "call",
		Attrs: waBinary.Attrs{"id": cli.GenerateMessageID(), "to": info.PeerJID},
		Content: []waBinary.Node{{
			Tag:     "relaylatency",
			Attrs:   waBinary.Attrs{"call-id": info.CallID, "call-creator": info.CallCreator, "count": "0"},
			Content: children,
		}},
	}
}

// BuildTransportStanza builds a <call><transport> stanza for ICE candidate exchange.
func (cli *Client) BuildTransportStanza(info *types.CallInfo) waBinary.Node {
	children := []waBinary.Node{
		{Tag: "net", Attrs: waBinary.Attrs{"protocol": "0", "medium": "2"}},
	}
	if destination, ok := buildCallDestinationNode(info); ok {
		children = append(children, destination)
	}
	return waBinary.Node{
		Tag:   "call",
		Attrs: waBinary.Attrs{"id": cli.GenerateMessageID(), "to": info.PeerJID},
		Content: []waBinary.Node{{
			Tag:     "transport",
			Attrs:   waBinary.Attrs{"call-id": info.CallID, "call-creator": info.CallCreator, "count": "0"},
			Content: children,
		}},
	}
}

// BuildMuteStanza builds a <call><mute_v2> stanza to change mute state.
func (cli *Client) BuildMuteStanza(info *types.CallInfo, muted bool) waBinary.Node {
	muteState := "0"
	if muted {
		muteState = "1"
	}

	return waBinary.Node{
		Tag:   "call",
		Attrs: waBinary.Attrs{"id": cli.GenerateMessageID(), "to": info.PeerJID},
		Content: []waBinary.Node{{
			Tag: "mute_v2",
			Attrs: waBinary.Attrs{
				"call-id":      info.CallID,
				"call-creator": info.CallCreator,
				"count":        "0",
				"mute-state":   muteState,
			},
		}},
	}
}

// BuildEncRekeyStanza builds a <call><enc_rekey> stanza with a new encrypted
// call key generation for long-running call key rotation.
func (cli *Client) BuildEncRekeyStanza(info *types.CallInfo, encCiphertext []byte, encType string, generation uint32) waBinary.Node {
	if generation == 0 {
		generation = 1
	}

	return waBinary.Node{
		Tag:   "call",
		Attrs: waBinary.Attrs{"id": cli.GenerateMessageID(), "to": info.PeerJID},
		Content: []waBinary.Node{{
			Tag:   "enc_rekey",
			Attrs: waBinary.Attrs{"call-id": info.CallID, "call-creator": info.CallCreator},
			Content: []waBinary.Node{{
				Tag:     "enc",
				Attrs:   waBinary.Attrs{"type": encType, "count": strconv.FormatUint(uint64(generation), 10)},
				Content: encCiphertext,
			}},
		}},
	}
}

// BuildCallAck builds an ack response for a call signaling message.
// WAWeb client ACKs are simple (no child element). The server-originated ACKs
// for relaylatency include a <relaylatency> child, but client-originated ACKs
// for incoming stanzas do not.
func BuildCallAck(stanzaID string, to types.JID, sigType types.SignalingType, callID string, callCreator types.JID) waBinary.Node {
	return waBinary.Node{
		Tag: "ack",
		Attrs: waBinary.Attrs{
			"to":    to,
			"id":    stanzaID,
			"class": "call",
			"type":  sigType.Tag(),
		},
	}
}

// BuildCallReceipt builds a receipt response for a call signaling message.
func BuildCallReceipt(stanzaID string, peerJID types.JID, selfJID types.JID, sigType types.SignalingType, callID string, callCreator types.JID) waBinary.Node {
	return waBinary.Node{
		Tag: "receipt",
		Attrs: waBinary.Attrs{
			"to":   peerJID,
			"id":   stanzaID,
			"from": selfJID,
			"type": "call",
		},
		Content: []waBinary.Node{{
			Tag: sigType.Tag(),
			Attrs: waBinary.Attrs{
				"call-id":      callID,
				"call-creator": callCreator,
			},
		}},
	}
}
