// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"bytes"
	"testing"

	"go.mau.fi/whatsmeow/types"
)

func TestParseTransportPayloadRaw(t *testing.T) {
	raw := []byte{0x01, 0x02, 0x03}
	parsed := ParseTransportPayload(raw)
	if parsed == nil {
		t.Fatalf("expected parsed payload")
	}
	if !bytes.Equal(parsed.RawData, raw) {
		t.Fatalf("unexpected raw data")
	}
	if parsed.Ufrag != "" || parsed.Pwd != "" || len(parsed.Candidates) != 0 {
		t.Fatalf("expected no structured fields for binary payload")
	}
}

func TestParseTransportPayloadJSON(t *testing.T) {
	jsonPayload := []byte(`{"ufrag":"abc","pwd":"xyz","candidates":[{"candidate":"candidate:1","sdp_mid":"0","sdp_m_line_index":1,"username_fragment":"abc"}]}`)
	parsed := ParseTransportPayload(jsonPayload)
	if parsed == nil {
		t.Fatalf("expected parsed payload")
	}
	if parsed.Ufrag != "abc" || parsed.Pwd != "xyz" {
		t.Fatalf("unexpected parsed credentials: %+v", parsed)
	}
	if len(parsed.Candidates) != 1 {
		t.Fatalf("expected one candidate, got %d", len(parsed.Candidates))
	}
	if parsed.Candidates[0].Candidate != "candidate:1" || parsed.Candidates[0].SDPMid != "0" {
		t.Fatalf("unexpected parsed candidate: %+v", parsed.Candidates[0])
	}
	if parsed.Candidates[0].SDPMLineIndex == nil || *parsed.Candidates[0].SDPMLineIndex != 1 {
		t.Fatalf("unexpected parsed sdp_m_line_index")
	}
}

func TestSerializeTransportPayload(t *testing.T) {
	lineIdx := uint16(2)
	payload := &types.TransportPayload{
		Ufrag: "u1",
		Pwd:   "p1",
		Candidates: []types.TransportCandidate{{
			Candidate:     "candidate:2",
			SDPMid:        "1",
			SDPMLineIndex: &lineIdx,
			UsernameFrag:  "u1",
		}},
	}
	data := SerializeTransportPayload(payload)
	if len(data) == 0 {
		t.Fatalf("expected serialized payload")
	}

	reparsed := ParseTransportPayload(data)
	if reparsed == nil {
		t.Fatalf("expected reparsed payload")
	}
	if reparsed.Ufrag != "u1" || reparsed.Pwd != "p1" {
		t.Fatalf("unexpected reparsed credentials: %+v", reparsed)
	}
	if len(reparsed.Candidates) != 1 || reparsed.Candidates[0].Candidate != "candidate:2" {
		t.Fatalf("unexpected reparsed candidates: %+v", reparsed.Candidates)
	}
}

func TestSerializeTransportPayloadUsesRawData(t *testing.T) {
	raw := []byte{9, 8, 7}
	payload := &types.TransportPayload{RawData: raw, Ufrag: "ignored"}
	serialized := SerializeTransportPayload(payload)
	if !bytes.Equal(serialized, raw) {
		t.Fatalf("expected raw serialization path")
	}
}
