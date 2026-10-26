// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nrf

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clock is a settable now for the token cache.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func oauthNRF(t *testing.T) (*fakeNRF, *Client, *clock, Profile) {
	t.Helper()
	nrf := newFakeNRF(t)
	nrf.oauth = true
	c := nrf.start(t)
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	c.tokens.now = clk.now
	p := registeredProfile(t, nrf, c)
	return nrf, c, clk, p
}

// No token until the NRF asks for one; then the one obtained goes with every request.
func TestClient_TokenOnDemand(t *testing.T) {
	nrf, c, _, p := oauthNRF(t)
	for range 2 {
		_, err := c.Heartbeat(context.Background(), p)
		require.NoError(t, err)
	}
	_, found, err := c.Retrieve(context.Background(), p)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, []string{"PUT", "PATCH", "TOKEN", "PATCH", "PATCH", "GET"}, nrf.callLog())

	require.Len(t, nrf.tokenReqs, 1)
	req := nrf.tokenReqs[0]
	assert.Equal(t, "client_credentials", req.Get("grant_type"))
	assert.Equal(t, p.InstanceID, req.Get("nfInstanceId"))
	assert.Equal(t, "UDM", req.Get("nfType"))
	assert.Equal(t, "NRF", req.Get("targetNfType"))
	assert.Equal(t, "nnrf-nfm", req.Get("scope"))
}

// The SMS-GMSC's tokens for its calls to the SMSF: asked for as that instance and NF type,
// for the producer's NF type and scope, kept apart from its NFManagement token.
func TestTokenSource(t *testing.T) {
	nrf, c, _, _ := oauthNRF(t)
	ps, err := Build([]byte(`{"profiles": [{"profile": {"nfInstanceId": "`+gmscID+`", "nfType": "SMS_GMSC", "fqdn": "gmsc.example"}}]}`),
		Options{TLS: true, OAuth: true}, testAPIs)
	require.NoError(t, err)
	gmsc := ps[0]
	_, err = c.Register(context.Background(), gmsc)
	require.NoError(t, err)
	_, err = c.Heartbeat(context.Background(), gmsc) // 401, then its nnrf-nfm token
	require.NoError(t, err)

	src := c.TokenSource(gmsc)
	tok, err := src.Token(context.Background(), "nsmsf-sms", "SMSF", "")
	require.NoError(t, err)
	again, err := src.Token(context.Background(), "nsmsf-sms", "SMSF", "")
	require.NoError(t, err)
	assert.Equal(t, tok, again, "cached")
	require.Len(t, nrf.tokenReqs, 2)
	req := nrf.tokenReqs[1]
	assert.Equal(t, gmscID, req.Get("nfInstanceId"))
	assert.Equal(t, "SMS_GMSC", req.Get("nfType"))
	assert.Equal(t, "SMSF", req.Get("targetNfType"))
	assert.Equal(t, "nsmsf-sms", req.Get("scope"))
	assert.NotEqual(t, tok, "token-1", "not the NFManagement token")

	src.Refused("nsmsf-sms", "SMSF", "", tok)
	renewed, err := src.Token(context.Background(), "nsmsf-sms", "SMSF", "")
	require.NoError(t, err)
	assert.NotEqual(t, tok, renewed, "a refused token is replaced")
	_, err = c.Heartbeat(context.Background(), gmsc)
	require.NoError(t, err)
	assert.Len(t, nrf.tokenReqs, 3, "the NFManagement token is kept")

	bound, err := src.Token(context.Background(), "nsmsf-sms", "SMSF", smsfID)
	require.NoError(t, err)
	assert.NotEqual(t, renewed, bound, "a token for one SMSF is its own")
	require.Len(t, nrf.tokenReqs, 4)
	assert.Equal(t, smsfID, nrf.tokenReqs[3].Get("targetNfInstanceId"))
	assert.Empty(t, nrf.tokenReqs[2].Get("targetNfInstanceId"))
}

// Each profile is its own NF instance and has its own token.
func TestClient_TokenPerProfile(t *testing.T) {
	nrf, c, _, udm := oauthNRF(t)
	ps, err := Build([]byte(twoProfiles), Options{TLS: true, OAuth: true}, testAPIs)
	require.NoError(t, err)
	udr := ps[1]
	_, err = c.Register(context.Background(), udr)
	require.NoError(t, err)
	for _, p := range []Profile{udm, udr, udm, udr} {
		_, err := c.Heartbeat(context.Background(), p)
		require.NoError(t, err)
	}
	require.Len(t, nrf.tokenReqs, 2)
	assert.Equal(t, "UDM", nrf.tokenReqs[0].Get("nfType"))
	assert.Equal(t, udr.InstanceID, nrf.tokenReqs[1].Get("nfInstanceId"))
	assert.Equal(t, "UDR", nrf.tokenReqs[1].Get("nfType"))
}

// A token is replaced refreshMargin before it expires, or at half its lifetime.
func TestClient_TokenRenewal(t *testing.T) {
	for name, tc := range map[string]struct {
		expiresIn   int
		early, late time.Duration
	}{
		"margin":        {expiresIn: 3600, early: 3569 * time.Second, late: 3570 * time.Second},
		"half lifetime": {expiresIn: 40, early: 19 * time.Second, late: 20 * time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			nrf, c, clk, p := oauthNRF(t)
			nrf.set(func(f *fakeNRF) { f.expiresIn = tc.expiresIn })
			start := clk.t
			_, err := c.Heartbeat(context.Background(), p) // 401, the first token
			require.NoError(t, err)
			clk.t = start.Add(tc.early)
			_, err = c.Heartbeat(context.Background(), p)
			require.NoError(t, err)
			assert.Len(t, nrf.tokenReqs, 1, "still the first")
			clk.t = start.Add(tc.late)
			_, err = c.Heartbeat(context.Background(), p)
			require.NoError(t, err)
			assert.Len(t, nrf.tokenReqs, 2, "renewed")
			assert.Equal(t, []string{"PUT", "PATCH", "TOKEN", "PATCH", "PATCH", "TOKEN", "PATCH"}, nrf.callLog())
		})
	}
}

// The NRF answers the renewal with an error: the token it has not expired yet serves on.
func TestClient_TokenRenewalFails(t *testing.T) {
	nrf, c, clk, p := oauthNRF(t)
	nrf.set(func(f *fakeNRF) { f.expiresIn = 60 })
	start := clk.t
	_, err := c.Heartbeat(context.Background(), p)
	require.NoError(t, err)
	nrf.set(func(f *fakeNRF) { f.tokenFail = http.StatusInternalServerError })
	clk.t = start.Add(45 * time.Second) // due for renewal, not expired
	_, err = c.Heartbeat(context.Background(), p)
	require.NoError(t, err)
	clk.t = start.Add(61 * time.Second) // expired: sent without one, refused
	_, err = c.Heartbeat(context.Background(), p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nrf heartbeat: HTTP 401, and no access token: HTTP 500")
	assert.Equal(t, []string{"PUT", "PATCH", "TOKEN", "PATCH", "TOKEN", "PATCH", "TOKEN", "PATCH"}, nrf.callLog())
}

// The NRF refuses a token it issued (it restarted with another key, say): a fresh one, once.
func TestClient_TokenRefused(t *testing.T) {
	nrf, c, _, p := oauthNRF(t)
	_, err := c.Heartbeat(context.Background(), p)
	require.NoError(t, err)
	nrf.set(func(f *fakeNRF) { clear(f.issued) })
	_, err = c.Heartbeat(context.Background(), p)
	require.NoError(t, err)
	assert.Equal(t, []string{"PUT", "PATCH", "TOKEN", "PATCH", "PATCH", "TOKEN", "PATCH"}, nrf.callLog())

	// Refused again: the 401 is the answer.
	nrf.set(func(f *fakeNRF) { f.oauth = false; f.fail = http.StatusUnauthorized })
	_, err = c.Heartbeat(context.Background(), p)
	var se *StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusUnauthorized, se.Status)
}

func TestClient_TokenErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		status   int
		body     string
		want     string
		wantCode string
	}{
		"AccessTokenErr": {status: http.StatusBadRequest, body: `{"error":"invalid_client","error_description":"unknown certificate"}`,
			want: "HTTP 400: invalid_client: unknown certificate", wantCode: "invalid_client"},
		"ProblemDetails": {status: http.StatusForbidden, body: `{"status":403,"cause":"NF_CONSUMER_NOT_ALLOWED","detail":"x"}`,
			want: "HTTP 403: NF_CONSUMER_NOT_ALLOWED x"},
		// free5GC's client cannot decode these; the status is kept.
		"no body":    {status: http.StatusNotFound, want: "HTTP 404"},
		"not JSON":   {status: http.StatusBadRequest, body: `<html>`, want: "HTTP 400"},
		"no token":   {status: http.StatusOK, body: `{"token_type":"Bearer"}`, want: "HTTP 200: the answer carries no Bearer access_token"},
		"not Bearer": {status: http.StatusOK, body: `{"access_token":"a","token_type":"MAC"}`, want: "HTTP 200: the answer carries no Bearer"},
	} {
		t.Run(name, func(t *testing.T) {
			nrf, c, _, p := oauthNRF(t)
			nrf.set(func(f *fakeNRF) { f.tokenFail, f.tokenBody = tc.status, tc.body })
			_, err := c.Heartbeat(context.Background(), p)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "nrf heartbeat: HTTP 401, and no access token: "+tc.want)
			var te *TokenError
			require.ErrorAs(t, err, &te)
			assert.Equal(t, tc.status, te.Status)
			assert.Equal(t, tc.wantCode, te.Code)
			assert.False(t, IsNotFound(err), "the token endpoint's 404 is not the instance's")
		})
	}
}

// An NRF that stops asking for tokens and stops issuing them is still reached.
func TestClient_NRFDropsOAuth(t *testing.T) {
	nrf, c, _, p := oauthNRF(t)
	_, err := c.Heartbeat(context.Background(), p)
	require.NoError(t, err)
	nrf.set(func(f *fakeNRF) { f.oauth, f.tokenFail = false, http.StatusBadRequest; clear(f.issued) })
	c.tokens.drop(p, scopeNFManagement, nfTypeNRF, "", "token-1")
	_, err = c.Heartbeat(context.Background(), p)
	require.NoError(t, err)
}

// The deregistration Job, against an NRF that wants tokens.
func TestDeregister_OAuth(t *testing.T) {
	nrf, c, _, p := oauthNRF(t)
	s := &script{steps: []func(){nil}}
	err := (&Deregisterer{Client: c, Profiles: []Profile{p}, Log: discard, sleep: s.sleep}).Run(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"PUT", "GET", "TOKEN", "GET", "DELETE", "DELETE"}, nrf.callLog())
	assert.False(t, nrf.registered(p.InstanceID))
}

// The token endpoint is at the NRF's scheme and authority, without the API root's prefix.
func TestNewClient_TokenEndpoint(t *testing.T) {
	c, err := NewClient("https://nrf.example:8443/prefix/", http.DefaultClient)
	require.NoError(t, err)
	assert.Equal(t, "https://nrf.example:8443", c.tokens.endpoint)
}

func TestTokenExpiry(t *testing.T) {
	jws := func(payload string) string {
		return "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
	}
	exp, ok := tokenExpiry(jws(`{"exp":1800000600,"scope":"nnrf-nfm"}`))
	require.True(t, ok)
	assert.Equal(t, time.Unix(1_800_000_600, 0), exp)
	for _, bad := range []string{"", "opaque", jws(`{}`), jws(`{"exp":"soon"}`), "e30.!!.sig"} {
		_, ok := tokenExpiry(bad)
		assert.False(t, ok, bad)
	}

	// Without expires_in the exp claim gives the lifetime; an opaque token serves one request.
	nrf, c, clk, p := oauthNRF(t)
	nrf.set(func(f *fakeNRF) { f.expiresIn, f.exp = 0, clk.t.Unix()+600 })
	_, lifetime, err := c.tokens.request(context.Background(), p, scopeNFManagement, nfTypeNRF, "")
	require.NoError(t, err)
	assert.Equal(t, 600*time.Second, lifetime)
	nrf.set(func(f *fakeNRF) { f.exp = 0 })
	_, lifetime, err = c.tokens.request(context.Background(), p, scopeNFManagement, nfTypeNRF, "")
	require.NoError(t, err)
	assert.Zero(t, lifetime)
	for range 2 {
		_, err = c.Heartbeat(context.Background(), p)
		require.NoError(t, err)
	}
	assert.Equal(t, []string{"PUT", "TOKEN", "TOKEN", "PATCH", "TOKEN", "PATCH", "TOKEN", "PATCH"}, nrf.callLog())
}

// An answer larger than maxBody is cut off, not read whole.
func TestTokens_BoundedAnswer(t *testing.T) {
	nrf, c, _, p := oauthNRF(t)
	nrf.set(func(f *fakeNRF) {
		f.tokenFail, f.tokenBody = http.StatusOK, `{"access_token":"`+strings.Repeat("a", maxBody)+`","token_type":"Bearer"}`
	})
	_, _, err := c.tokens.request(context.Background(), p, scopeNFManagement, nfTypeNRF, "")
	var te *TokenError
	require.ErrorAs(t, err, &te)
	assert.Equal(t, http.StatusOK, te.Status)
}
