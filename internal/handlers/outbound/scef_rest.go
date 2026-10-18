// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import "context"

// scefRestClient is a stub: scef_rest profile delivers via an external SCEF
// adapter that reads the same NATS event independently. From this gateway's
// perspective the call is bypassed — see ErrBypassed.
type scefRestClient struct{}

// NewSCEFRest returns a bypass client. All Send calls return ErrBypassed.
func NewSCEFRest() Client { return scefRestClient{} }

func (scefRestClient) Profile() Profile { return ProfileSCEFRest }

func (scefRestClient) Send(_ context.Context, _ *Request) (*Response, error) {
	return nil, ErrBypassed
}
