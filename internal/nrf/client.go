// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nrf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
)

// Client calls the NRF's Nnrf_NFManagement API (TS 29.510 clause 6.1).
//
// The API admits requests without an access token and with one of scope nnrf-nfm (its
// OpenAPI's security), so the NRF decides: once it answers 401, the client obtains tokens
// from it (Nnrf_AccessToken, clause 5.4) and sends one with every request.
type Client struct {
	root   string // {apiRoot}
	base   string // {apiRoot}/nnrf-nfm/v1/nf-instances/
	http   *http.Client
	tokens *tokens
	oauth  atomic.Bool // the NRF answered 401
}

// StatusError is an NRF answer other than the operation's success.
type StatusError struct {
	Operation string
	Status    int
	Body      string // the start of the body: a ProblemDetails, usually
}

func (e *StatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("nrf %s: HTTP %d", e.Operation, e.Status)
	}
	return fmt.Sprintf("nrf %s: HTTP %d: %s", e.Operation, e.Status, e.Body)
}

// IsNotFound reports whether err is the NRF answering that it does not know the instance.
func IsNotFound(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Status == http.StatusNotFound
}

const maxBody = 64 << 10

// NewClient returns a client of the NRF at apiRoot (TS 29.501 clause 4.4.1:
// scheme://host[:port][/prefix]). hc must speak HTTP/2 (TS 29.500 clause 5.2.1); the NRF's
// redirections (307, 308) are followed with the method and body. Access tokens come from
// the token endpoint at apiRoot's scheme and authority (TS 29.510 clause 5.4.2.2.1).
func NewClient(apiRoot string, hc *http.Client) (*Client, error) {
	u, err := url.Parse(apiRoot)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, fmt.Errorf("NRF_API_ROOT %q: want http(s)://host[:port][/prefix]", apiRoot)
	}
	root := strings.TrimSuffix(apiRoot, "/")
	return &Client{
		root:   root,
		base:   root + "/nnrf-nfm/v1/nf-instances/",
		http:   hc,
		tokens: newTokens(u.Scheme+"://"+u.Host, hc),
	}, nil
}

// Register PUTs the profile (TS 29.510 clause 5.2.2.2.2, or 5.2.2.3.1 when the instance
// exists) and returns the heartbeat interval the NRF answered with; 0 when it gave none.
func (c *Client) Register(ctx context.Context, p Profile) (time.Duration, error) {
	resp, err := c.do(ctx, p, "register", http.MethodPut, "application/json", p.Body)
	if err != nil {
		return 0, err
	}
	if resp.status != http.StatusCreated && resp.status != http.StatusOK {
		return 0, resp.err("register")
	}
	return heartBeatTimer(resp.body), nil
}

// heartbeatPatch is the heartbeat of TS 29.510 clause 5.2.2.3.2: a replace of nfStatus.
var heartbeatPatch = []byte(`[{"op":"replace","path":"/nfStatus","value":"REGISTERED"}]`)

// Heartbeat sends the instance's heartbeat (TS 29.510 clause 5.2.2.3.2). It returns the
// heartbeat interval when the NRF answered with the profile (200) and the profile carries
// one; 0 otherwise. A 404 is a StatusError IsNotFound recognises: the NRF does not know
// the instance (any more).
func (c *Client) Heartbeat(ctx context.Context, p Profile) (time.Duration, error) {
	resp, err := c.do(ctx, p, "heartbeat", http.MethodPatch, "application/json-patch+json", heartbeatPatch)
	if err != nil {
		return 0, err
	}
	switch resp.status {
	case http.StatusNoContent:
		return 0, nil
	case http.StatusOK:
		return heartBeatTimer(resp.body), nil
	}
	return 0, resp.err("heartbeat")
}

// Retrieve reads the registered profile's heartbeat interval (NFProfileRetrieval, TS 29.510
// clause 5.2.2.9). found is false on 404.
func (c *Client) Retrieve(ctx context.Context, p Profile) (heartbeat time.Duration, found bool, err error) {
	resp, err := c.do(ctx, p, "retrieve", http.MethodGet, "", nil)
	if err != nil {
		return 0, false, err
	}
	switch resp.status {
	case http.StatusOK:
		return heartBeatTimer(resp.body), true, nil
	case http.StatusNotFound:
		return 0, false, nil
	}
	return 0, false, resp.err("retrieve")
}

// Deregister removes the instance (TS 29.510 clause 5.2.2.4). existed is false when the NRF
// answered 404: it did not know the instance.
func (c *Client) Deregister(ctx context.Context, p Profile) (existed bool, err error) {
	resp, err := c.do(ctx, p, "deregister", http.MethodDelete, "", nil)
	if err != nil {
		return false, err
	}
	switch resp.status {
	case http.StatusNoContent:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	}
	return false, resp.err("deregister")
}

type response struct {
	status int
	body   []byte
}

func (r response) err(op string) error {
	snippet := r.body
	if len(snippet) > 512 {
		snippet = snippet[:512]
	}
	return &StatusError{Operation: op, Status: r.status, Body: strings.TrimSpace(string(snippet))}
}

// do sends the request, with an access token once the NRF asked for one. A 401 is answered
// with a fresh token, once: the NRF asks for one, or refused the one sent (expired early, or
// signed with a key it has since replaced).
func (c *Client) do(ctx context.Context, p Profile, op, method, contentType string, body []byte) (response, error) {
	var token string
	var tokenErr error
	if c.oauth.Load() {
		// Without one the request still goes: the NRF may no longer ask for it.
		token, tokenErr = c.tokens.get(ctx, p, scopeNFManagement, nfTypeNRF, "")
	}
	resp, err := c.send(ctx, p, op, method, contentType, body, token)
	if err != nil || resp.status != http.StatusUnauthorized {
		return resp, err
	}
	c.oauth.Store(true)
	if tokenErr == nil {
		if token != "" {
			c.tokens.drop(p, scopeNFManagement, nfTypeNRF, "", token)
		}
		if token, tokenErr = c.tokens.get(ctx, p, scopeNFManagement, nfTypeNRF, ""); tokenErr == nil {
			return c.send(ctx, p, op, method, contentType, body, token)
		}
	}
	return response{}, fmt.Errorf("nrf %s: HTTP 401, and no %w", op, tokenErr)
}

func (c *Client) send(ctx context.Context, p Profile, op, method, contentType string, body []byte, token string) (response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body) // GetBody is set: a 307/308 is followed with the body
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+p.InstanceID, rd)
	if err != nil {
		return response{}, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json, application/problem+json")
	req.Header.Set("User-Agent", userAgent(p))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		metrics.RecordNRFRequest(p.Type, op, "error", false)
		return response{}, fmt.Errorf("nrf %s: %w", op, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		metrics.RecordNRFRequest(p.Type, op, "error", false)
		return response{}, fmt.Errorf("nrf %s: reading the answer: %w", op, err)
	}
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	metrics.RecordNRFRequest(p.Type, op, strconv.Itoa(resp.StatusCode), ok)
	return response{status: resp.StatusCode, body: data}, nil
}

// heartBeatTimer reads an NFProfile's heartBeatTimer (seconds); 0 when it has none.
func heartBeatTimer(body []byte) time.Duration {
	var p struct {
		HeartBeatTimer int `json:"heartBeatTimer"`
	}
	if json.Unmarshal(body, &p) != nil || p.HeartBeatTimer <= 0 {
		return 0
	}
	return time.Duration(p.HeartBeatTimer) * time.Second
}
