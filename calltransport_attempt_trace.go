// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import "context"

type callTransportAttemptTraceContextKey struct{}

type callTransportAttemptTrace struct {
	AttemptID string
	Source    string
}

func withCallTransportAttemptTrace(ctx context.Context, attemptID, source string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, callTransportAttemptTraceContextKey{}, callTransportAttemptTrace{
		AttemptID: attemptID,
		Source:    source,
	})
}

func callTransportAttemptTraceFromContext(ctx context.Context) (attemptID, source string) {
	if ctx == nil {
		return "", ""
	}
	value := ctx.Value(callTransportAttemptTraceContextKey{})
	trace, ok := value.(callTransportAttemptTrace)
	if !ok {
		return "", ""
	}
	return trace.AttemptID, trace.Source
}

func shortCallID(callID string) string {
	if len(callID) <= 8 {
		return callID
	}
	return callID[:8]
}
