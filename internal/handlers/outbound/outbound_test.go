// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package outbound_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers/outbound"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/sbi"
	"github.com/stretchr/testify/assert"
)

func TestProfile_Validate(t *testing.T) {
	cases := []struct {
		in outbound.Profile
		ok bool
	}{
		{outbound.ProfileSBIDirect, true},
		{outbound.ProfileSCEFRest, true},
		{outbound.ProfileMtcIwfRest, true},
		{outbound.ProfileScefRestHTTPS, true},
		{outbound.Profile(""), false},
		{outbound.Profile("scef-rest"), false}, // wrong separator
	}
	for _, c := range cases {
		err := c.in.Validate()
		if c.ok {
			assert.NoError(t, err, "profile %q", c.in)
		} else {
			assert.Error(t, err, "profile %q", c.in)
		}
	}
}

func TestNotImplementedProfiles_FailLoudWithTypedError(t *testing.T) {
	cases := []struct {
		profile outbound.Profile
		want    error
	}{
		{outbound.ProfileMtcIwfRest, outbound.ErrMtcIwfNotImplemented},
		{outbound.ProfileScefRestHTTPS, outbound.ErrScefNotImplemented},
	}
	for _, c := range cases {
		t.Run(string(c.profile), func(t *testing.T) {
			client, err := outbound.New(c.profile, nil)
			assert.NoError(t, err, "factory must accept the profile (operator boots even when peering pending)")
			assert.Equal(t, c.profile, client.Profile())

			resp, err := client.Send(context.Background(), &outbound.Request{CallbackURI: "x"})
			assert.Nil(t, resp)
			assert.True(t, errors.Is(err, c.want),
				"Send must return the typed sentinel, got %v", err)
			// Distinguish from the existing ErrBypassed path: not-implemented
			// is a fault, not a delegation.
			assert.False(t, errors.Is(err, outbound.ErrBypassed),
				"not-implemented sentinels must NOT be confused with ErrBypassed")
		})
	}
}

func TestNew_UnknownProfile(t *testing.T) {
	_, err := outbound.New("does-not-exist", nil)
	assert.Error(t, err)
}

func TestSCEFRest_AlwaysBypasses(t *testing.T) {
	c, err := outbound.New(outbound.ProfileSCEFRest, nil)
	assert.NoError(t, err)
	assert.Equal(t, outbound.ProfileSCEFRest, c.Profile())

	resp, err := c.Send(context.Background(), &outbound.Request{
		TargetNF:    "amf-1",
		CallbackURI: "http://amf-1/cb",
	})
	assert.Nil(t, resp)
	assert.True(t, errors.Is(err, outbound.ErrBypassed),
		"scef_rest must signal bypass via ErrBypassed; got %v", err)
}

func TestSBIDirect_RejectsMissingCallback(t *testing.T) {
	c, err := outbound.New(outbound.ProfileSBIDirect, nil)
	assert.NoError(t, err)
	assert.Equal(t, outbound.ProfileSBIDirect, c.Profile())

	resp, err := c.Send(context.Background(), &outbound.Request{TargetNF: "amf-1"})
	assert.Nil(t, resp)
	assert.Error(t, err)
	assert.False(t, errors.Is(err, outbound.ErrBypassed),
		"missing-callback is a real error, not a bypass")
}

func TestSBIDirect_NilRequest(t *testing.T) {
	c, _ := outbound.New(outbound.ProfileSBIDirect, nil)
	resp, err := c.Send(context.Background(), nil)
	assert.Nil(t, resp)
	assert.Error(t, err)
}

func TestSBIDirect_PropagatesHTTPStatus_5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"cause":"NF_CONGESTION"}`))
	}))
	defer srv.Close()

	amf := sbi.NewAmfClient()
	amf.Client.Transport = http.DefaultTransport
	c, _ := outbound.New(outbound.ProfileSBIDirect, amf)

	resp, err := c.Send(context.Background(), &outbound.Request{CallbackURI: srv.URL})
	assert.Error(t, err, "5xx must surface as error so the failover loop sees it")
	if assert.NotNil(t, resp) {
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		assert.Contains(t, string(resp.Body), "NF_CONGESTION")
	}

	var httpErr *sbi.HTTPError
	if assert.True(t, errors.As(err, &httpErr)) {
		assert.True(t, httpErr.IsRetryable(), "503 must be retryable")
	}
}

func TestSBIDirect_PropagatesHTTPStatus_4xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	amf := sbi.NewAmfClient()
	amf.Client.Transport = http.DefaultTransport
	c, _ := outbound.New(outbound.ProfileSBIDirect, amf)

	_, err := c.Send(context.Background(), &outbound.Request{CallbackURI: srv.URL})
	var httpErr *sbi.HTTPError
	if assert.True(t, errors.As(err, &httpErr)) {
		assert.False(t, httpErr.IsRetryable(),
			"403 must NOT be retryable — caller error, no failover")
	}
}
