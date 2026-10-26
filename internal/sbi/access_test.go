// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package sbi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeTokens is an NRF's token endpoint: it issues "token-<n>", or fails with err.
type fakeTokens struct {
	mu      sync.Mutex
	err     error
	issued  int
	current string
	asked   []string // scope and target of each request, and the target instance when set
	refused []string
}

func (f *fakeTokens) Token(_ context.Context, scope, target, instance string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.current != "" {
		return f.current, nil
	}
	f.asked = append(f.asked, strings.TrimSpace(scope+" "+target+" "+instance))
	if f.err != nil {
		return "", f.err
	}
	f.issued++
	f.current = "token-" + strconv.Itoa(f.issued)
	return f.current, nil
}

func (f *fakeTokens) Refused(_, _, _, token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refused = append(f.refused, token)
	if f.current == token {
		f.current = ""
	}
}

// producer answers 401 to calls without a token it accepts, 200 otherwise, and records the
// Authorization of each call.
type producer struct {
	mu       sync.Mutex
	accept   func(token string) bool
	received []string
}

func (p *producer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	p.received = append(p.received, token)
	if p.accept != nil && !p.accept(token) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="nsmsf-sms"`) // TS 29.500 clause 6.7.3
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusOK)
}

var smsfAccess = Access{Scope: "nsmsf-sms", TargetNfType: "SMSF"}

// clientWith calls p over https: tokens go over TLS alone.
func clientWith(t *testing.T, p *producer, tokens Tokens) (*AmfClient, string) {
	t.Helper()
	srv := httptest.NewTLSServer(p)
	t.Cleanup(srv.Close)
	c := &AmfClient{Client: srv.Client(), Tokens: tokens}
	return c, srv.URL + "/nsmsf-sms/v2/ue-contexts/imsi-001/send-mt-sms"
}

func postSMS(c *AmfClient, uri string, a Access) error {
	_, err := c.PostMultipart(context.Background(), uri, Multipart{JSON: []byte(`{}`), Binary: []byte{1}, BinaryType: "application/vnd.3gpp.sms", ContentID: "sms"}, a)
	return err
}

// A producer that asks for no token gets none, and no token is asked for.
func TestAccess_NoTokenUntilAsked(t *testing.T) {
	p := &producer{}
	tokens := &fakeTokens{}
	c, uri := clientWith(t, p, tokens)
	for range 2 {
		if err := postSMS(c, uri, smsfAccess); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(p.received, []string{"", ""}) || len(tokens.asked) != 0 {
		t.Errorf("received %q, tokens asked %q", p.received, tokens.asked)
	}
}

// The first 401 is answered with a token; the producer's later calls carry it from the start.
func TestAccess_TokenOnDemand(t *testing.T) {
	p := &producer{accept: func(tok string) bool { return tok == "token-1" }}
	tokens := &fakeTokens{}
	c, uri := clientWith(t, p, tokens)
	for range 2 {
		if err := postSMS(c, uri, smsfAccess); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(p.received, []string{"", "token-1", "token-1"}) {
		t.Errorf("received %q", p.received)
	}
	if !slices.Equal(tokens.asked, []string{"nsmsf-sms SMSF"}) {
		t.Errorf("tokens asked %q", tokens.asked)
	}
}

// A token the producer refuses is replaced, once; a second 401 is the producer's answer.
func TestAccess_RefusedTokenReplacedOnce(t *testing.T) {
	p := &producer{accept: func(tok string) bool { return tok == "token-2" }}
	tokens := &fakeTokens{}
	c, uri := clientWith(t, p, tokens)
	err := postSMS(c, uri, smsfAccess) // "" then token-1: both 401
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("err %v, want HTTP 401", err)
	}
	if err := postSMS(c, uri, smsfAccess); err != nil { // token-1 refused, token-2 accepted
		t.Fatal(err)
	}
	if !slices.Equal(p.received, []string{"", "token-1", "token-1", "token-2"}) || !slices.Equal(tokens.refused, []string{"token-1"}) {
		t.Errorf("received %q, refused %q", p.received, tokens.refused)
	}
}

// A producer asking for a token the NRF does not give: ErrNoAccessToken, which is transient.
func TestAccess_NoToken(t *testing.T) {
	p := &producer{accept: func(string) bool { return false }}
	nrfDown := errors.New("access token: connection refused")
	c, uri := clientWith(t, p, &fakeTokens{err: nrfDown})
	err := postSMS(c, uri, smsfAccess)
	if !errors.Is(err, ErrNoAccessToken) || !errors.Is(err, nrfDown) {
		t.Fatalf("err %v, want ErrNoAccessToken wrapping the NRF's failure", err)
	}
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		t.Error("not an HTTPError: a 4xx would end the delivery")
	}
}

// Calls without an Access (notifications) never carry a token: a 401 is the answer.
func TestAccess_NoneWithoutAccess(t *testing.T) {
	p := &producer{accept: func(string) bool { return false }}
	tokens := &fakeTokens{}
	c, uri := clientWith(t, p, tokens)
	err := c.SendCallback(context.Background(), uri, map[string]string{})
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("err %v, want HTTP 401", err)
	}
	if err := postSMS(c, uri, Access{}); !errors.As(err, &httpErr) {
		t.Fatalf("err %v, want HTTP 401", err)
	}
	if len(tokens.asked) != 0 || len(p.received) != 2 {
		t.Errorf("tokens asked %q, calls %d", tokens.asked, len(p.received))
	}
}

// A producer reached over http (h2c) is sent no token: the 401 is its answer.
func TestAccess_NoTokenOverCleartext(t *testing.T) {
	p := &producer{accept: func(string) bool { return false }}
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	tokens := &fakeTokens{}
	c := &AmfClient{Client: srv.Client(), Tokens: tokens}
	for range 2 {
		err := postSMS(c, srv.URL+"/nsmsf-sms/v2/ue-contexts/imsi-001/send-mt-sms", smsfAccess)
		var httpErr *HTTPError
		if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusUnauthorized {
			t.Fatalf("err %v, want HTTP 401", err)
		}
	}
	if len(tokens.asked) != 0 || !slices.Equal(p.received, []string{"", ""}) {
		t.Errorf("tokens asked %q, received %q", tokens.asked, p.received)
	}
}
