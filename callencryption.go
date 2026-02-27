// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"go.mau.fi/libsignal/keys/prekey"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/session"
	"go.mau.fi/libsignal/signalerror"
	"google.golang.org/protobuf/proto"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/hkdfutil"
)

const pkcs7BlockSize = 16

var errCallKeySignalPanic = errors.New("libsignal panic during call key crypto")

// CallEncryptionKey holds the master encryption key for a call.
type CallEncryptionKey struct {
	MasterKey  [32]byte
	Generation uint32
}

// CallOfferEncryptedTarget represents encrypted call-key material for one
// destination device in WAWeb-style offer fanout.
type CallOfferEncryptedTarget struct {
	JID        types.JID
	Ciphertext []byte
	EncType    string
	Count      uint32
}

// Zeroize clears sensitive key material in-place (best-effort).
func (k *CallEncryptionKey) Zeroize() {
	if k == nil {
		return
	}
	for i := range k.MasterKey {
		k.MasterKey[i] = 0
	}
	k.Generation = 0
}

// SRTPKeyingMaterial holds SRTP master key and salt per RFC 3711.
type SRTPKeyingMaterial struct {
	MasterKey  [16]byte
	MasterSalt [14]byte
}

// Zeroize clears SRTP key material in-place (best-effort).
func (m *SRTPKeyingMaterial) Zeroize() {
	if m == nil {
		return
	}
	for i := range m.MasterKey {
		m.MasterKey[i] = 0
	}
	for i := range m.MasterSalt {
		m.MasterSalt[i] = 0
	}
}

// DerivedCallKeys holds all keys derived from the call master key.
type DerivedCallKeys struct {
	HBHSRTP       SRTPKeyingMaterial // Hop-by-hop SRTP (client <-> relay)
	UplinkSRTCP   SRTPKeyingMaterial // Client -> relay
	DownlinkSRTCP SRTPKeyingMaterial // Relay -> client
	E2ESFrame     [32]byte           // End-to-end sframe key
	WARPAuth      [32]byte           // WARP authentication key
}

// Zeroize clears all derived key material in-place (best-effort).
func (d *DerivedCallKeys) Zeroize() {
	if d == nil {
		return
	}
	d.HBHSRTP.Zeroize()
	d.UplinkSRTCP.Zeroize()
	d.DownlinkSRTCP.Zeroize()
	for i := range d.E2ESFrame {
		d.E2ESFrame[i] = 0
	}
	for i := range d.WARPAuth {
		d.WARPAuth[i] = 0
	}
}

// GenerateCallKey creates a new random 32-byte call encryption key.
func GenerateCallKey() (CallEncryptionKey, error) {
	var key CallEncryptionKey
	if _, err := rand.Read(key.MasterKey[:]); err != nil {
		return CallEncryptionKey{}, fmt.Errorf("failed to generate call key: %w", err)
	}
	key.Generation = 1
	return key, nil
}

// EncryptCallKey encrypts a call key for a recipient using the Signal protocol.
// Returns the ciphertext and encryption type ("msg" or "pkmsg").
func (cli *Client) EncryptCallKey(ctx context.Context, recipient types.JID, key *CallEncryptionKey) ([]byte, string, bool, error) {
	targets, includeIdentity, err := cli.EncryptCallKeyForOffer(ctx, recipient, key)
	if err != nil {
		return nil, "", false, err
	}
	if len(targets) == 0 {
		return nil, "", false, fmt.Errorf("no encrypted call key targets generated")
	}
	return targets[0].Ciphertext, targets[0].EncType, includeIdentity, nil
}

// EncryptCallKeyForOffer encrypts call-key material for all known recipient
// devices and returns WAWeb-style offer destination targets.
func (cli *Client) EncryptCallKeyForOffer(ctx context.Context, recipient types.JID, key *CallEncryptionKey) ([]CallOfferEncryptedTarget, bool, error) {
	if key == nil {
		return nil, false, fmt.Errorf("call key is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	recipient = cli.resolveCallKeyEncryptRecipientJID(ctx, recipient).ToNonAD()

	msg := &waE2E.Message{
		Call: &waE2E.Call{
			CallKey: key.MasterKey[:],
		},
	}
	plaintext, err := proto.Marshal(msg)
	if err != nil {
		return nil, false, fmt.Errorf("failed to marshal call key protobuf: %w", err)
	}

	// PKCS7 padding (call keys use PKCS7, not random padding)
	plaintext = padPKCS7(plaintext)

	targetJIDs, err := cli.resolveCallOfferTargetDevices(ctx, recipient)
	if err != nil {
		return nil, false, err
	}
	if len(targetJIDs) == 0 {
		targetJIDs = []types.JID{recipient}
	}

	var pnTargets []types.JID
	for _, jid := range targetJIDs {
		if jid.Server == types.DefaultUserServer {
			pnTargets = append(pnTargets, jid)
		}
	}
	lidMappings, err := cli.Store.LIDs.GetManyLIDsForPNs(ctx, pnTargets)
	if err != nil {
		return nil, false, fmt.Errorf("failed to fetch LID mappings for call key encryption: %w", err)
	}

	encryptionIdentities := make(map[types.JID]types.JID, len(targetJIDs))
	sessionAddressToJID := make(map[string]types.JID, len(targetJIDs))
	sessionAddresses := make([]string, 0, len(targetJIDs))
	for _, jid := range targetJIDs {
		encryptionIdentity := jid
		if jid.Server == types.DefaultUserServer {
			if lidForPN, ok := lidMappings[jid]; ok && !lidForPN.IsEmpty() {
				cli.migrateSessionStore(ctx, jid, lidForPN)
				encryptionIdentity = lidForPN
			}
		}
		encryptionIdentities[jid] = encryptionIdentity
		addr := encryptionIdentity.SignalAddress().String()
		sessionAddresses = append(sessionAddresses, addr)
		sessionAddressToJID[addr] = jid
	}

	existingSessions, cachedCtx, err := cli.Store.WithCachedSessions(ctx, sessionAddresses)
	if err != nil {
		return nil, false, fmt.Errorf("failed to prefetch call sessions: %w", err)
	}

	var retryDevices []types.JID
	for addr, exists := range existingSessions {
		if !exists {
			retryDevices = append(retryDevices, sessionAddressToJID[addr])
		}
	}
	bundles := cli.fetchPreKeysNoError(cachedCtx, retryDevices)

	targets := make([]CallOfferEncryptedTarget, 0, len(targetJIDs))
	includeIdentity := false
	for _, wireJID := range targetJIDs {
		encrypted, preKeyUsed, encErr := cli.encryptCallKeyForSignalIdentity(
			cachedCtx,
			encryptionIdentities[wireJID],
			bundles[wireJID],
			existingSessions,
			plaintext,
		)
		if encErr != nil {
			if cachedCtx.Err() != nil {
				return nil, false, encErr
			}
			cli.Log.Warnf("Failed to encrypt call key for %s: %v", wireJID, encErr)
			continue
		}
		targets = append(targets, CallOfferEncryptedTarget{
			JID:        wireJID,
			Ciphertext: encrypted.Serialize(),
			EncType:    encTypeFromCiphertext(encrypted),
			Count:      0,
		})
		if preKeyUsed {
			includeIdentity = true
		}
	}

	if err = cli.Store.PutCachedSessions(cachedCtx); err != nil {
		return nil, false, fmt.Errorf("failed to save cached sessions after call key encryption: %w", err)
	}
	if len(targets) == 0 {
		return nil, false, fmt.Errorf("failed to encrypt call key for any recipient device")
	}
	return targets, includeIdentity && cli.MessengerConfig == nil, nil
}

func (cli *Client) resolveCallOfferTargetDevices(ctx context.Context, recipient types.JID) ([]types.JID, error) {
	if recipient.Server != types.DefaultUserServer && recipient.Server != types.HiddenUserServer {
		return []types.JID{recipient.ToNonAD()}, nil
	}
	devices, err := cli.GetUserDevices(ctx, []types.JID{recipient.ToNonAD()})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch call recipient devices: %w", err)
	}
	if len(devices) == 0 {
		return []types.JID{recipient.ToNonAD()}, nil
	}
	return devices, nil
}

func (cli *Client) encryptCallKeyForSignalIdentity(
	ctx context.Context,
	to types.JID,
	bundle *prekey.Bundle,
	existingSessions map[string]bool,
	plaintext []byte,
) (protocol.CiphertextMessage, bool, error) {
	builder := session.NewBuilderFromSignal(cli.Store, to.SignalAddress(), pbSerializer)
	if bundle != nil {
		err := builder.ProcessBundle(ctx, bundle)
		if cli.AutoTrustIdentity && errors.Is(err, signalerror.ErrUntrustedIdentity) {
			cli.Log.Warnf("Got %v while processing call prekey bundle for %s, clearing identity and retrying", err, to)
			err = cli.clearUntrustedIdentity(ctx, to)
			if err != nil {
				return nil, false, fmt.Errorf("failed to clear untrusted identity: %w", err)
			}
			err = builder.ProcessBundle(ctx, bundle)
		}
		if err != nil {
			return nil, false, fmt.Errorf("failed to process call prekey bundle: %w", err)
		}
	} else {
		sessionExists, checked := existingSessions[to.SignalAddress().String()]
		if !checked {
			var err error
			sessionExists, err = cli.Store.ContainsSession(ctx, to.SignalAddress())
			if err != nil {
				return nil, false, err
			}
		}
		if !sessionExists {
			return nil, false, fmt.Errorf("%w with %s", ErrNoSession, to.SignalAddress().String())
		}
	}

	cipher := session.NewCipher(builder, to.SignalAddress())
	ciphertext, err := callKeySignalGuard("encrypt", func() (protocol.CiphertextMessage, error) {
		return cipher.Encrypt(ctx, plaintext)
	})
	if err != nil {
		return nil, false, fmt.Errorf("failed to encrypt call key: %w", err)
	}
	return ciphertext, ciphertext.Type() == protocol.PREKEY_TYPE, nil
}

func encTypeFromCiphertext(ciphertext protocol.CiphertextMessage) string {
	if ciphertext != nil && ciphertext.Type() == protocol.PREKEY_TYPE {
		return "pkmsg"
	}
	return "msg"
}

func (cli *Client) resolveCallKeyEncryptRecipientJID(ctx context.Context, recipient types.JID) types.JID {
	if recipient.Server != types.DefaultUserServer || cli == nil || cli.Store == nil || cli.Store.LIDs == nil {
		return recipient
	}

	lookupPN := recipient.ToNonAD()
	lid, err := cli.Store.LIDs.GetLIDForPN(ctx, lookupPN)
	if err != nil {
		if cli.Log != nil {
			cli.Log.Warnf("Failed to resolve LID for call key recipient %s: %v", recipient, err)
		}
		return recipient
	}
	if lid.IsEmpty() {
		return recipient
	}
	if lid.Device == 0 && recipient.Device != 0 {
		lid.Device = recipient.Device
	}
	cli.migrateSessionStore(ctx, recipient, lid)
	return lid
}

// DecryptCallKey decrypts an encrypted call key received from a sender.
func (cli *Client) DecryptCallKey(ctx context.Context, from types.JID, ciphertext []byte, encType string) (*CallEncryptionKey, error) {
	builder := session.NewBuilderFromSignal(cli.Store, from.SignalAddress(), pbSerializer)
	cipher := session.NewCipher(builder, from.SignalAddress())

	var plaintext []byte
	var err error

	switch encType {
	case "pkmsg":
		preKeyMsg, parseErr := protocol.NewPreKeySignalMessageFromBytes(ciphertext, pbSerializer.PreKeySignalMessage, pbSerializer.SignalMessage)
		if parseErr != nil {
			return nil, fmt.Errorf("failed to parse prekey call key message: %w", parseErr)
		}
		plaintext, err = callKeySignalGuard("decrypt-prekey", func() ([]byte, error) {
			return cipher.DecryptMessage(ctx, preKeyMsg)
		})
	case "msg":
		signalMsg, parseErr := protocol.NewSignalMessageFromBytes(ciphertext, pbSerializer.SignalMessage)
		if parseErr != nil {
			return nil, fmt.Errorf("failed to parse call key message: %w", parseErr)
		}
		plaintext, err = callKeySignalGuard("decrypt", func() ([]byte, error) {
			return cipher.Decrypt(ctx, signalMsg)
		})
	default:
		return nil, fmt.Errorf("unknown call key encryption type: %s", encType)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt call key: %w", err)
	}

	// PKCS7 unpadding
	plaintext, err = unpadPKCS7(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to unpad call key: %w", err)
	}

	// Unmarshal protobuf
	var msg waE2E.Message
	if err = proto.Unmarshal(plaintext, &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal call key protobuf: %w", err)
	}

	masterKey, err := extractCallMasterKey(&msg)
	if err != nil {
		return nil, err
	}
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("call key wrong length: expected 32, got %d", len(masterKey))
	}

	var key CallEncryptionKey
	copy(key.MasterKey[:], masterKey)
	key.Generation = 1
	return &key, nil
}

func extractCallMasterKey(msg *waE2E.Message) ([]byte, error) {
	if msg == nil {
		return nil, fmt.Errorf("call key message is nil")
	}
	if bcall := msg.GetBcallMessage(); bcall != nil {
		if key := bcall.GetMasterKey(); len(key) > 0 {
			return key, nil
		}
	}
	if call := msg.GetCall(); call != nil {
		if key := call.GetCallKey(); len(key) > 0 {
			return key, nil
		}
	}
	return nil, fmt.Errorf("call key message missing call key field")
}

// DeriveCallKeys derives all SRTP and media keys from the call master key using HKDF-SHA256.
func DeriveCallKeys(key *CallEncryptionKey) *DerivedCallKeys {
	derived := &DerivedCallKeys{}

	// SRTP keying material: 30 bytes each (16-byte key + 14-byte salt)
	hbh := hkdfutil.SHA256(key.MasterKey[:], nil, []byte("hbh srtp key"), 30)
	copy(derived.HBHSRTP.MasterKey[:], hbh[:16])
	copy(derived.HBHSRTP.MasterSalt[:], hbh[16:30])
	zeroizeBytes(hbh)

	uplink := hkdfutil.SHA256(key.MasterKey[:], nil, []byte("uplink hbh srtcp key"), 30)
	copy(derived.UplinkSRTCP.MasterKey[:], uplink[:16])
	copy(derived.UplinkSRTCP.MasterSalt[:], uplink[16:30])
	zeroizeBytes(uplink)

	downlink := hkdfutil.SHA256(key.MasterKey[:], nil, []byte("downlink hbh srtcp key"), 30)
	copy(derived.DownlinkSRTCP.MasterKey[:], downlink[:16])
	copy(derived.DownlinkSRTCP.MasterSalt[:], downlink[16:30])
	zeroizeBytes(downlink)

	// 32-byte keys
	e2e := hkdfutil.SHA256(key.MasterKey[:], nil, []byte("e2e sframe key"), 32)
	copy(derived.E2ESFrame[:], e2e)
	zeroizeBytes(e2e)

	warp := hkdfutil.SHA256(key.MasterKey[:], nil, []byte("warp auth key"), 32)
	copy(derived.WARPAuth[:], warp)
	zeroizeBytes(warp)

	return derived
}

func zeroizeBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func callKeySignalGuard[T any](op string, fn func() (T, error)) (out T, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("%w (%s): %v", errCallKeySignalPanic, op, recovered)
		}
	}()
	return fn()
}

func padPKCS7(data []byte) []byte {
	paddingLen := pkcs7BlockSize - (len(data) % pkcs7BlockSize)
	padded := make([]byte, len(data)+paddingLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(paddingLen)
	}
	return padded
}

func unpadPKCS7(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data for PKCS7 unpad")
	}
	paddingLen := int(data[len(data)-1])
	if paddingLen == 0 || paddingLen > pkcs7BlockSize || paddingLen > len(data) {
		return nil, fmt.Errorf("invalid PKCS7 padding")
	}
	for i := len(data) - paddingLen; i < len(data); i++ {
		if int(data[i]) != paddingLen {
			return nil, fmt.Errorf("invalid PKCS7 padding bytes")
		}
	}
	return data[:len(data)-paddingLen], nil
}

// parseEncData extracts encryption data from a call stanza child node.
func parseEncData(child *waBinary.Node) *types.OfferEncData {
	enc := child.GetChildByTag("enc")
	if enc.Tag == "" {
		return nil
	}
	ag := enc.AttrGetter()
	content, ok := decodeBase64OrRawBytes(enc.Content)
	if !ok {
		return nil
	}
	return &types.OfferEncData{
		EncType:    ag.String("type"),
		Ciphertext: content,
		Version:    ag.Int("v"),
	}
}
