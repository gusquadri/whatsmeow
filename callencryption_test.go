// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

type testCallEncryptLIDStore struct {
	store.NoopStore
	lidByPN    map[string]types.JID
	migrations [][2]types.JID
}

func (s *testCallEncryptLIDStore) GetLIDForPN(_ context.Context, pn types.JID) (types.JID, error) {
	if s.lidByPN == nil {
		return types.EmptyJID, nil
	}
	if mapped, ok := s.lidByPN[pn.User]; ok {
		out := mapped
		out.Device = pn.Device
		return out, nil
	}
	return types.EmptyJID, nil
}

func (s *testCallEncryptLIDStore) MigratePNToLID(_ context.Context, pn, lid types.JID) error {
	s.migrations = append(s.migrations, [2]types.JID{pn, lid})
	return nil
}

func TestCallKeySignalGuardRecoversPanic(t *testing.T) {
	_, err := callKeySignalGuard("encrypt", func() ([]byte, error) {
		panic("broken session state")
	})
	if err == nil {
		t.Fatalf("expected panic recovery error")
	}
	if !errors.Is(err, errCallKeySignalPanic) {
		t.Fatalf("expected errCallKeySignalPanic, got %v", err)
	}
}

func TestCallKeySignalGuardPassesThroughReturn(t *testing.T) {
	out, err := callKeySignalGuard("encrypt", func() (string, error) {
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "ok" {
		t.Fatalf("unexpected output: %q", out)
	}
}

func TestResolveCallKeyEncryptRecipientJIDUsesLIDMapping(t *testing.T) {
	own := types.NewJID("15550001", types.DefaultUserServer)
	pn := types.NewJID("15550002", types.DefaultUserServer)
	lid := types.NewJID("99887766", types.HiddenUserServer)
	mock := &testCallEncryptLIDStore{
		lidByPN: map[string]types.JID{
			pn.User: lid,
		},
	}
	cli := &Client{
		Store: &store.Device{
			ID:       &own,
			LIDs:     mock,
			Sessions: mock,
		},
	}

	got := cli.resolveCallKeyEncryptRecipientJID(context.Background(), pn)
	if got != lid {
		t.Fatalf("unexpected resolved recipient: got %s want %s", got, lid)
	}
	if len(mock.migrations) != 1 {
		t.Fatalf("expected one migration, got %d", len(mock.migrations))
	}
	if !reflect.DeepEqual(mock.migrations[0], [2]types.JID{pn, lid}) {
		t.Fatalf("unexpected migration pair: %+v", mock.migrations[0])
	}
}

func TestResolveCallKeyEncryptRecipientJIDFallsBackToPN(t *testing.T) {
	own := types.NewJID("15550001", types.DefaultUserServer)
	pn := types.NewJID("15550002", types.DefaultUserServer)
	mock := &testCallEncryptLIDStore{}
	cli := &Client{
		Store: &store.Device{
			ID:       &own,
			LIDs:     mock,
			Sessions: mock,
		},
	}

	got := cli.resolveCallKeyEncryptRecipientJID(context.Background(), pn)
	if got != pn {
		t.Fatalf("unexpected fallback recipient: got %s want %s", got, pn)
	}
	if len(mock.migrations) != 0 {
		t.Fatalf("expected no migrations, got %d", len(mock.migrations))
	}
}

func TestExtractCallMasterKeyFromCallMessage(t *testing.T) {
	expected := make([]byte, 32)
	for i := range expected {
		expected[i] = byte(i + 1)
	}
	msg := &waE2E.Message{
		Call: &waE2E.Call{
			CallKey: expected,
		},
	}

	got, err := extractCallMasterKey(msg)
	if err != nil {
		t.Fatalf("extractCallMasterKey returned error: %v", err)
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("unexpected master key bytes")
	}
}

func TestExtractCallMasterKeyFromBCallMessage(t *testing.T) {
	expected := make([]byte, 32)
	for i := range expected {
		expected[i] = byte(0xFF - i)
	}
	msg := &waE2E.Message{
		BcallMessage: &waE2E.BCallMessage{
			MasterKey: expected,
		},
	}

	got, err := extractCallMasterKey(msg)
	if err != nil {
		t.Fatalf("extractCallMasterKey returned error: %v", err)
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("unexpected master key bytes")
	}
}

func TestExtractCallMasterKeyMissingField(t *testing.T) {
	_, err := extractCallMasterKey(&waE2E.Message{})
	if err == nil {
		t.Fatalf("expected error when call key field is missing")
	}
}
