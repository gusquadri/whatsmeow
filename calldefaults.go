// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

func newDefaultCallTransport() CallTransport {
	return &NoopCallTransport{}
}

func newDefaultCallMediaEngine() CallMediaEngine {
	return NewRTPCallMediaEngine(
		DefaultRTPCallMediaEngineConfig(),
		OpusPacketCodec{},
		PassThroughVideoCodec{},
		CallMediaIO{},
	)
}
