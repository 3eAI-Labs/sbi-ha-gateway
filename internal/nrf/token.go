// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nrf

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/nrf/AccTok"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
)

// scopeNFManagement is the scope of the Nnrf_NFManagement API (TS 29.510 clause 6.1, the
// securitySchemes of its OpenAPI).
const scopeNFManagement = "nnrf-nfm"

// nfTypeNRF is the NF type of the NFManagement API's producer, a token's targetNfType.
const nfTypeNRF = string(models.Nrf_NFMgmt_NFType_NRF)

// refreshMargin: a token is replaced this long before it expires, or at half its lifetime
// when that is shorter, so that a request it goes with reaches the NRF in time. The
// gateway's choice.
const refreshMargin = 30 * time.Second

// TokenError is the NRF refusing an access token request, or not answering it.
type TokenError struct {
	Status      int    // 0: no HTTP answer
	Code        string // the AccessTokenErr error (IETF RFC 6749 clause 5.2), e.g. invalid_client
	Description string // its error_description, or a ProblemDetails' cause and detail
	Err         error
}

func (e *TokenError) Error() string {
	var b strings.Builder
	b.WriteString("access token")
	if e.Status != 0 {
		fmt.Fprintf(&b, ": HTTP %d", e.Status)
	}
	for _, s := range []string{e.Code, e.Description} {
		if s != "" {
			b.WriteString(": " + s)
		}
	}
	if e.Code == "" && e.Description == "" && e.Err != nil {
		b.WriteString(": " + e.Err.Error())
	}
	return b.String()
}

func (e *TokenError) Unwrap() error { return e.Err }

// unknownClient reports whether err is the NRF refusing a token as invalid_client: it does
// not recognise the requesting instance (IETF RFC 6749 clause 5.2).
func unknownClient(err error) bool {
	var te *TokenError
	return errors.As(err, &te) && te.Code == "invalid_client"
}

// tokens obtains access tokens from the NRF (Nnrf_AccessToken_Get, TS 29.510 clause 5.4.2.2:
// the client credentials grant) with free5GC's generated client, one per NF profile, scope,
// producer NF type and producer instance (when the token is asked for one), and keeps each
// until shortly before it expires.
type tokens struct {
	endpoint string // {nrfApiRoot}: the scheme and authority alone (TS 29.510 clause 5.4.2.2.1)
	http     *http.Client
	now      func() time.Time

	mu    sync.Mutex
	cache map[tokenKey]*tokenEntry
}

type tokenKey struct{ instance, scope, target, targetInstance string }

type tokenEntry struct {
	mu      sync.Mutex // one request per key at a time; the others wait for its token
	token   string
	renewAt time.Time
	expires time.Time
}

func newTokens(endpoint string, hc *http.Client) *tokens {
	// free5GC's client reads the answer whole: bound it as the NFManagement answers are.
	limited := *hc
	limited.Transport = limitBodies{base: hc.Transport}
	return &tokens{endpoint: endpoint, http: &limited, now: time.Now, cache: map[tokenKey]*tokenEntry{}}
}

func (t *tokens) entry(k tokenKey) *tokenEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.cache[k]
	if e == nil {
		e = &tokenEntry{}
		t.cache[k] = e
	}
	return e
}

// get returns a token for p's instance, to scope at producers of NF type target, or at the
// instance targetInstance alone when it is not empty: the cached one until it is due for
// renewal, else a new one. When renewal fails, the cached token serves until it expires.
func (t *tokens) get(ctx context.Context, p Profile, scope, target, targetInstance string) (string, error) {
	e := t.entry(tokenKey{p.InstanceID, scope, target, targetInstance})
	e.mu.Lock()
	defer e.mu.Unlock()
	now := t.now()
	if e.token != "" && now.Before(e.renewAt) {
		return e.token, nil
	}
	token, lifetime, err := t.request(ctx, p, scope, target, targetInstance)
	if err != nil {
		if e.token != "" && t.now().Before(e.expires) {
			return e.token, nil
		}
		e.token = ""
		return "", err
	}
	// Without a lifetime the token is used for this request alone.
	e.token, e.expires, e.renewAt = token, now.Add(lifetime), now.Add(lifetime-min(refreshMargin, lifetime/2))
	return token, nil
}

// drop forgets token, which the NRF refused, unless a newer one already replaced it.
func (t *tokens) drop(p Profile, scope, target, targetInstance, token string) {
	e := t.entry(tokenKey{p.InstanceID, scope, target, targetInstance})
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.token == token {
		e.token = ""
	}
}

// request asks the NRF for a token for p's NF type and instance, to scope at producers of NF
// type target, with targetInstance as the targetNfInstanceId when it is not empty (the
// token's audience is then that instance), and returns it with its lifetime: expires_in,
// else the token's exp claim; 0 when it has neither.
func (t *tokens) request(ctx context.Context, p Profile, scope, target, targetInstance string) (string, time.Duration, error) {
	status := 0 // the answer's, even when free5GC's client cannot decode its body
	cfg := AccTok.NewConfiguration()
	cfg.SetBasePath(t.endpoint)
	cfg.SetHTTPClient(t.http)
	cfg.SetUserAgent(userAgent(p))
	cfg.SetMetrics(func(_, _ string, s int, _ float64) { status = s })
	req := &AccTok.AccessTokenRequestRequest{}
	req.SetGrantType("client_credentials")
	req.SetNfInstanceId(p.InstanceID)
	req.SetNfType(models.Nrf_NFMgmt_NFType(p.Type))
	req.SetTargetNfType(models.Nrf_NFMgmt_NFType(target))
	if targetInstance != "" {
		req.SetTargetNfInstanceId(targetInstance)
	}
	req.SetScope(scope)
	rsp, err := AccTok.NewAPIClient(cfg).AccessTokenRequestApi.AccessTokenRequest(ctx, req)
	if err == nil && (rsp.Nrf_AccTok_AccessTokenRsp == nil || rsp.Nrf_AccTok_AccessTokenRsp.Access_token == "" ||
		!strings.EqualFold(rsp.Nrf_AccTok_AccessTokenRsp.Token_type, "Bearer")) {
		err = errors.New("the answer carries no Bearer access_token")
	}
	result := "error"
	if status != 0 {
		result = strconv.Itoa(status)
	}
	metrics.RecordNRFRequest(p.Type, "token", result, err == nil)
	if err != nil {
		return "", 0, tokenError(status, err)
	}
	r := rsp.Nrf_AccTok_AccessTokenRsp
	if r.Expires_in > 0 {
		return r.Access_token, time.Duration(r.Expires_in) * time.Second, nil
	}
	if exp, ok := tokenExpiry(r.Access_token); ok {
		return r.Access_token, max(exp.Sub(t.now()), 0), nil
	}
	return r.Access_token, 0, nil
}

// TokenSource gives one profile's access tokens for the gateway's calls to other network
// functions, as that NF instance: the SMS-GMSC's for Nsmsf_SMService MtForwardSm.
type TokenSource struct {
	tokens  *tokens
	profile Profile
}

// TokenSource returns p's access tokens, obtained from this client's NRF.
func (c *Client) TokenSource(p Profile) *TokenSource { return &TokenSource{c.tokens, p} }

// Token returns a token to scope at producers of NF type target (e.g. nsmsf-sms, SMSF), or
// at the instance targetInstance alone when it is not empty.
func (s *TokenSource) Token(ctx context.Context, scope, target, targetInstance string) (string, error) {
	return s.tokens.get(ctx, s.profile, scope, target, targetInstance)
}

// Refused forgets token, which a producer refused, so that the next Token asks for a new one.
func (s *TokenSource) Refused(scope, target, targetInstance, token string) {
	s.tokens.drop(s.profile, scope, target, targetInstance, token)
}

func tokenError(status int, err error) *TokenError {
	te := &TokenError{Status: status, Err: err}
	var ae openapi.GenericOpenAPIError
	if !errors.As(err, &ae) {
		return te
	}
	te.Status = ae.ErrorStatus
	m, _ := ae.ErrorModel.(AccTok.AccessTokenRequestError)
	switch {
	case m.Nrf_AccTok_AccessTokenErr != nil:
		te.Code, te.Description = m.Nrf_AccTok_AccessTokenErr.Error, m.Nrf_AccTok_AccessTokenErr.Error_description
	case m.ProblemDetails != nil:
		te.Description = strings.TrimSpace(m.ProblemDetails.Cause + " " + m.ProblemDetails.Detail)
	}
	return te
}

// tokenExpiry reads the exp claim of a JWS compact serialization, unverified: the NRF and
// the producers verify the token; the gateway only schedules its renewal.
func tokenExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var c struct {
		Exp float64 `json:"exp"`
	}
	if json.Unmarshal(payload, &c) != nil || c.Exp <= 0 {
		return time.Time{}, false
	}
	return time.Unix(int64(c.Exp), 0), true
}

// userAgent identifies the requesting NF (TS 29.500 clause 5.2.2.2: the NF type, then "-"
// and what else identifies it).
func userAgent(p Profile) string { return p.Type + "-" + p.InstanceID }

// limitBodies bounds the bodies of the answers to maxBody.
type limitBodies struct{ base http.RoundTripper }

func (l limitBodies) RoundTrip(r *http.Request) (*http.Response, error) {
	base := l.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(r)
	if resp != nil {
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.LimitReader(resp.Body, maxBody), resp.Body}
	}
	return resp, err
}
