// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"context"
	"errors"
	"net/http"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/sbi"
)

// sbiDirectClient delivers outbound calls via the native HTTP/2 SBI client.
// It wraps the existing sbi.AmfClient; future NF-aware discovery can be layered
// on top without changing this interface.
type sbiDirectClient struct {
	http *sbi.AmfClient
}

// NewSBIDirect builds a Client backed by the supplied AmfClient.
// Pass nil to use the package-default AmfClient.
func NewSBIDirect(httpClient *sbi.AmfClient) Client {
	if httpClient == nil {
		httpClient = sbi.NewAmfClient()
	}
	return &sbiDirectClient{http: httpClient}
}

func (c *sbiDirectClient) Profile() Profile { return ProfileSBIDirect }

// Send POSTs req.Payload to req.CallbackURI. On HTTP failure the underlying
// *sbi.HTTPError is returned unwrapped; callers can errors.As it to read
// status code and decide retry/failover. Transport failures come back as
// plain errors (no HTTPError) — those are always failover candidates.
func (c *sbiDirectClient) Send(ctx context.Context, req *Request) (*Response, error) {
	if req == nil {
		return nil, errors.New("outbound: nil request")
	}
	if req.CallbackURI == "" {
		// CallbackURI resolution via NRF is a follow-up; today we require it from the caller.
		return nil, errors.New("outbound: CallbackURI is required for sbi_direct profile")
	}

	if req.Multipart != nil {
		parts, err := c.http.PostMultipart(ctx, req.CallbackURI, *req.Multipart)
		if err != nil {
			var httpErr *sbi.HTTPError
			if errors.As(err, &httpErr) {
				return &Response{StatusCode: httpErr.StatusCode, Body: httpErr.Body}, err
			}
			return nil, err
		}
		return &Response{StatusCode: http.StatusOK, Multipart: parts}, nil
	}

	if err := c.http.SendCallback(ctx, req.CallbackURI, req.Payload); err != nil {
		// On *sbi.HTTPError, surface the actual status so callers can branch
		// on 4xx vs 5xx. On transport errors, StatusCode stays 0.
		var httpErr *sbi.HTTPError
		if errors.As(err, &httpErr) {
			return &Response{StatusCode: httpErr.StatusCode, Body: httpErr.Body}, err
		}
		return nil, err
	}

	// 2xx — body not surfaced (AmfClient discards it on success).
	return &Response{StatusCode: 200}, nil
}
