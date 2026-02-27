// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"strconv"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
)

// runCallStartPreflight sends WAWeb-like call preflight requests before
// encrypted offer construction.
func (cli *Client) runCallStartPreflight(ctx context.Context, peerJID types.JID) {
	if cli == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// WAWeb emits unified_session around call startup.
	if err := cli.sendUnifiedSessionWithContext(ctx); err != nil {
		cli.Log.Debugf("Failed to send unified_session in call preflight: %v", err)
	}
	if err := cli.syncVoIPDeviceList(ctx, peerJID); err != nil {
		cli.Log.Debugf("Failed voip usync preflight for %s: %v", peerJID, err)
	}
}

func (cli *Client) sendUnifiedSessionWithContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	return cli.sendNode(ctx, waBinary.Node{
		Tag: "ib",
		Content: []waBinary.Node{{
			Tag: "unified_session",
			Attrs: waBinary.Attrs{
				"id": cli.getUnifiedSessionID(),
			},
		}},
	})
}

func (cli *Client) syncVoIPDeviceList(ctx context.Context, peerJID types.JID) error {
	peer := peerJID.ToNonAD()
	if peer.Server != types.DefaultUserServer && peer.Server != types.HiddenUserServer {
		return nil
	}
	deviceHash, ts := cli.getCachedVoIPDeviceSyncHint(peer)
	requestID := cli.generateRequestID()
	usyncNode := buildVoIPUSyncDevicesNode(requestID, peer, deviceHash, ts)
	resp, err := cli.sendIQ(ctx, infoQuery{
		Namespace: "usync",
		Type:      iqGet,
		To:        types.ServerJID,
		Content:   []waBinary.Node{usyncNode},
	})
	if err != nil {
		return err
	}

	list, ok := resp.GetOptionalChildByTag("usync", "list")
	if !ok {
		return &ElementMissingError{Tag: "list", In: "response to voip usync query"}
	}
	cli.cacheVoIPUSyncDeviceList(&list)
	return nil
}

func buildVoIPUSyncDevicesNode(sid string, peerJID types.JID, deviceHash string, ts int64) waBinary.Node {
	userNode := waBinary.Node{
		Tag:   "user",
		Attrs: waBinary.Attrs{"jid": peerJID.ToNonAD()},
	}
	if deviceHash != "" {
		deviceAttrs := waBinary.Attrs{"device_hash": deviceHash}
		if ts > 0 {
			deviceAttrs["ts"] = strconv.FormatInt(ts, 10)
		}
		userNode.Content = []waBinary.Node{{
			Tag:   "devices",
			Attrs: deviceAttrs,
		}}
	}
	return waBinary.Node{
		Tag: "usync",
		Attrs: waBinary.Attrs{
			"sid":     sid,
			"mode":    "query",
			"last":    "true",
			"index":   "0",
			"context": "voip",
		},
		Content: []waBinary.Node{
			{
				Tag: "query",
				Content: []waBinary.Node{{
					Tag:   "devices",
					Attrs: waBinary.Attrs{"version": "2"},
				}},
			},
			{
				Tag:     "list",
				Content: []waBinary.Node{userNode},
			},
		},
	}
}

func (cli *Client) getCachedVoIPDeviceSyncHint(peerJID types.JID) (string, int64) {
	peer := peerJID.ToNonAD()
	cli.userDevicesCacheLock.Lock()
	defer cli.userDevicesCacheLock.Unlock()
	if cached, ok := cli.userDevicesCache[peer]; ok {
		if cached.dhash != "" {
			return cached.dhash, cached.ts
		}
	}
	return "", 0
}

func (cli *Client) cacheVoIPUSyncDeviceList(list *waBinary.Node) {
	if list == nil {
		return
	}
	nowTS := time.Now().Unix()
	cli.userDevicesCacheLock.Lock()
	defer cli.userDevicesCacheLock.Unlock()
	if cli.userDevicesCache == nil {
		cli.userDevicesCache = make(map[types.JID]deviceCache)
	}
	for _, user := range list.GetChildren() {
		jid, jidOK := user.Attrs["jid"].(types.JID)
		if user.Tag != "user" || !jidOK {
			continue
		}
		userDevices := parseDeviceList(jid, user.GetChildByTag("devices"))
		if len(userDevices) == 0 {
			continue
		}
		cli.userDevicesCache[jid] = deviceCache{
			devices: userDevices,
			dhash:   participantListHashV2(userDevices),
			ts:      nowTS,
		}
	}
}

func (cli *Client) cacheCallAckUserDevices(userDevices map[types.JID][]types.JID) {
	if len(userDevices) == 0 {
		return
	}
	nowTS := time.Now().Unix()
	cli.userDevicesCacheLock.Lock()
	defer cli.userDevicesCacheLock.Unlock()
	if cli.userDevicesCache == nil {
		cli.userDevicesCache = make(map[types.JID]deviceCache)
	}
	for userJID, devices := range userDevices {
		user := userJID.ToNonAD()
		if user.IsEmpty() || len(devices) == 0 {
			continue
		}
		copied := make([]types.JID, 0, len(devices))
		for _, device := range devices {
			copied = append(copied, device.ToNonAD())
		}
		cli.userDevicesCache[user] = deviceCache{
			devices: copied,
			dhash:   participantListHashV2(copied),
			ts:      nowTS,
		}
	}
}
