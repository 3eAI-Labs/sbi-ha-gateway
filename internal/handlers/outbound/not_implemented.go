// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import "context"

// notImplementedClient is the placeholder profile implementation for
// transports the operator has not yet peered with (MTC-IWF, SCEF HTTPS).
// Send always returns the typed sentinel; the failover loop in the NATS
// subscriber surfaces this as a non-retryable, non-failover client error
// so dashboards distinguish "peering pending" from "transport flaky".
type notImplementedClient struct {
	prof Profile
	err  error
}

func (c notImplementedClient) Profile() Profile { return c.prof }

func (c notImplementedClient) Send(_ context.Context, _ *Request) (*Response, error) {
	return nil, c.err
}
