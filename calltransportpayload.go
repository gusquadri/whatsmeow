// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"encoding/json"

	"go.mau.fi/whatsmeow/types"
)

type transportJSON struct {
	Ufrag      string                   `json:"ufrag,omitempty"`
	Pwd        string                   `json:"pwd,omitempty"`
	Candidates []transportCandidateJSON `json:"candidates,omitempty"`
}

type transportCandidateJSON struct {
	Candidate     string  `json:"candidate"`
	SDPMid        string  `json:"sdp_mid,omitempty"`
	SDPMLineIndex *uint16 `json:"sdp_m_line_index,omitempty"`
	UsernameFrag  string  `json:"username_fragment,omitempty"`
}

// ParseTransportPayload parses raw transport payload bytes.
//
// Raw bytes are always preserved in the returned payload. If the payload looks
// like JSON, common ICE fields are parsed into structured form.
func ParseTransportPayload(data []byte) *types.TransportPayload {
	if len(data) == 0 {
		return nil
	}
	payload := &types.TransportPayload{RawData: append([]byte(nil), data...)}
	if data[0] != '{' {
		return payload
	}

	var parsed transportJSON
	if err := json.Unmarshal(data, &parsed); err != nil {
		return payload
	}
	payload.Ufrag = parsed.Ufrag
	payload.Pwd = parsed.Pwd
	if len(parsed.Candidates) > 0 {
		payload.Candidates = make([]types.TransportCandidate, 0, len(parsed.Candidates))
		for _, candidate := range parsed.Candidates {
			payload.Candidates = append(payload.Candidates, types.TransportCandidate{
				Candidate:     candidate.Candidate,
				SDPMid:        candidate.SDPMid,
				SDPMLineIndex: candidate.SDPMLineIndex,
				UsernameFrag:  candidate.UsernameFrag,
			})
		}
	}
	return payload
}

// SerializeTransportPayload serializes structured transport payload data.
//
// If RawData is set, it is returned as-is. Otherwise, the structured fields
// are serialized as JSON.
func SerializeTransportPayload(payload *types.TransportPayload) []byte {
	if payload == nil {
		return nil
	}
	if len(payload.RawData) > 0 {
		return append([]byte(nil), payload.RawData...)
	}
	jsonPayload := transportJSON{
		Ufrag: payload.Ufrag,
		Pwd:   payload.Pwd,
	}
	if len(payload.Candidates) > 0 {
		jsonPayload.Candidates = make([]transportCandidateJSON, 0, len(payload.Candidates))
		for _, candidate := range payload.Candidates {
			jsonPayload.Candidates = append(jsonPayload.Candidates, transportCandidateJSON{
				Candidate:     candidate.Candidate,
				SDPMid:        candidate.SDPMid,
				SDPMLineIndex: candidate.SDPMLineIndex,
				UsernameFrag:  candidate.UsernameFrag,
			})
		}
	}
	data, err := json.Marshal(jsonPayload)
	if err != nil {
		return nil
	}
	return data
}
