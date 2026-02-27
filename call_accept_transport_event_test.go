package whatsmeow

import (
	"context"
	"testing"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
)

func TestHandleCallEventAcceptEnsuresTransportAndEmitsConnected(t *testing.T) {
	peer := types.NewJID("109822716420216", types.HiddenUserServer)
	creator := types.NewJID("102765716062358", types.HiddenUserServer)
	callID := "C1AA5034DB509CB0B7504242D4905666"

	cli := &Client{Log: waLog.Noop}
	cm := NewCallManager(cli)
	cli.callManager = cm
	cm.SetTransport(&testCallTransport{})
	cm.calls[callID] = &types.CallInfo{
		CallID:         callID,
		PeerJID:        peer,
		CallCreator:    creator,
		State:          types.CallStateRinging,
		TransportState: types.TransportStatePendingRelay,
		RelayData:      &types.RelayData{},
	}

	connectedCh := make(chan *events.CallTransportConnected, 1)
	acceptCh := make(chan *events.CallAccept, 1)
	handlerID := cli.AddEventHandler(func(evt any) {
		switch e := evt.(type) {
		case *events.CallTransportConnected:
			select {
			case connectedCh <- e:
			default:
			}
		case *events.CallAccept:
			select {
			case acceptCh <- e:
			default:
			}
		}
	})
	defer cli.RemoveEventHandler(handlerID)

	cli.handleCallEvent(context.Background(), &waBinary.Node{
		Tag: "call",
		Attrs: waBinary.Attrs{
			"from": peer,
			"id":   "4102.6866-891",
			"t":    "1771764523",
		},
		Content: []waBinary.Node{{
			Tag: "accept",
			Attrs: waBinary.Attrs{
				"call-id":      callID,
				"call-creator": creator,
			},
			Content: []waBinary.Node{{
				Tag:   "audio",
				Attrs: waBinary.Attrs{"enc": "opus", "rate": "16000"},
			}},
		}},
	})

	select {
	case evt := <-acceptCh:
		if evt.CallID != callID {
			t.Fatalf("unexpected accept call id: %s", evt.CallID)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected CallAccept event")
	}

	select {
	case evt := <-connectedCh:
		if evt.CallID != callID {
			t.Fatalf("unexpected transport-connected call id: %s", evt.CallID)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected CallTransportConnected event")
	}

	info := cm.GetCall(callID)
	if info == nil {
		t.Fatalf("expected call info to exist")
	}
	if info.State != types.CallStateActive {
		t.Fatalf("expected call state active, got %v", info.State)
	}
	if info.TransportState != types.TransportStateConnected {
		t.Fatalf("expected transport state connected, got %v", info.TransportState)
	}
}

func TestHandleCallEventAcceptForEndedCallIsIgnored(t *testing.T) {
	peer := types.NewJID("109822716420216", types.HiddenUserServer)
	creator := types.NewJID("102765716062358", types.HiddenUserServer)
	callID := "ENDED_CALL_ACCEPT_SHOULD_BE_IGNORED"

	cli := &Client{Log: waLog.Noop}
	cm := NewCallManager(cli)
	cli.callManager = cm
	cm.SetTransport(&testCallTransport{})
	cm.calls[callID] = &types.CallInfo{
		CallID:         callID,
		PeerJID:        peer,
		CallCreator:    creator,
		State:          types.CallStateEnded,
		TransportState: types.TransportStatePendingRelay,
		RelayData:      &types.RelayData{},
	}

	connectedCh := make(chan *events.CallTransportConnected, 1)
	acceptCh := make(chan *events.CallAccept, 1)
	handlerID := cli.AddEventHandler(func(evt any) {
		switch e := evt.(type) {
		case *events.CallTransportConnected:
			select {
			case connectedCh <- e:
			default:
			}
		case *events.CallAccept:
			select {
			case acceptCh <- e:
			default:
			}
		}
	})
	defer cli.RemoveEventHandler(handlerID)

	cli.handleCallEvent(context.Background(), &waBinary.Node{
		Tag: "call",
		Attrs: waBinary.Attrs{
			"from": peer,
			"id":   "4102.6866-999",
			"t":    "1771764523",
		},
		Content: []waBinary.Node{{
			Tag: "accept",
			Attrs: waBinary.Attrs{
				"call-id":      callID,
				"call-creator": creator,
			},
		}},
	})

	select {
	case evt := <-acceptCh:
		t.Fatalf("did not expect accept event for ended call: %+v", evt)
	case <-time.After(200 * time.Millisecond):
	}
	select {
	case evt := <-connectedCh:
		t.Fatalf("did not expect transport-connected event for ended call: %+v", evt)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestHandleCallEventAcceptDoesNotEmitConnectedWhenTransportStillConnecting(t *testing.T) {
	peer := types.NewJID("109822716420216", types.HiddenUserServer)
	creator := types.NewJID("102765716062358", types.HiddenUserServer)
	callID := "ACCEPT_WHILE_CONNECTING_SHOULD_EMIT_CONNECTED"

	cli := &Client{Log: waLog.Noop}
	cm := NewCallManager(cli)
	cli.callManager = cm
	// Keep a no-op transport; call starts in "connecting", so EnsureTransport is a no-op.
	cm.SetTransport(&testCallTransport{})
	cm.calls[callID] = &types.CallInfo{
		CallID:         callID,
		PeerJID:        peer,
		CallCreator:    creator,
		State:          types.CallStateConnecting,
		TransportState: types.TransportStateConnecting,
	}

	connectedCh := make(chan *events.CallTransportConnected, 1)
	connectedStateCh := make(chan *events.CallWebRTCTransportState, 1)
	handlerID := cli.AddEventHandler(func(evt any) {
		if e, ok := evt.(*events.CallTransportConnected); ok {
			select {
			case connectedCh <- e:
			default:
			}
		}
		if e, ok := evt.(*events.CallWebRTCTransportState); ok {
			select {
			case connectedStateCh <- e:
			default:
			}
		}
	})
	defer cli.RemoveEventHandler(handlerID)

	cli.handleCallEvent(context.Background(), &waBinary.Node{
		Tag: "call",
		Attrs: waBinary.Attrs{
			"from": peer,
			"id":   "4102.6866-connecting",
			"t":    "1771764523",
		},
		Content: []waBinary.Node{{
			Tag: "accept",
			Attrs: waBinary.Attrs{
				"call-id":      callID,
				"call-creator": creator,
			},
		}},
	})

	select {
	case evt := <-connectedCh:
		t.Fatalf("did not expect CallTransportConnected event while transport is still connecting: %+v", evt)
	case <-time.After(300 * time.Millisecond):
	}
	select {
	case evt := <-connectedStateCh:
		t.Fatalf("did not expect connected transport-state event while transport is still connecting: %+v", evt)
	case <-time.After(300 * time.Millisecond):
	}
}
