// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package sbi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAmfClient_SendCallback(t *testing.T) {
	// 1. Setup Mock AMF Server
	mockAMF := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Method
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		// Verify Header
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json")
		}

		// Verify Payload
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("Failed to decode body: %v", err)
		}
		if payload["event"] != "DATA_CHANGE" {
			t.Errorf("Expected event DATA_CHANGE, got %s", payload["event"])
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer mockAMF.Close()

	// 2. Initialize Client
	client := NewAmfClient()
	client.Client.Transport = http.DefaultTransport // Override HTTP/2 transport for testing

	// 3. Execute Test
	payload := map[string]string{"event": "DATA_CHANGE"}
	err := client.SendCallback(context.Background(), mockAMF.URL, payload)

	// 4. Assertions
	if err != nil {
		t.Fatalf("SendCallback failed: %v", err)
	}
}

func TestAmfClient_SendCallback_5xxIsRetryable(t *testing.T) {
	mockAMF := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"cause":"INTERNAL_ERROR"}`))
	}))
	defer mockAMF.Close()

	client := NewAmfClient()
	client.Client.Transport = http.DefaultTransport // httptest is HTTP/1.1
	err := client.SendCallback(context.Background(), mockAMF.URL, nil)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("expected *HTTPError, got %T: %v", err, err)
	}
	if httpErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d", httpErr.StatusCode)
	}
	if !httpErr.IsRetryable() {
		t.Error("500 must be retryable")
	}
	if string(httpErr.Body) != `{"cause":"INTERNAL_ERROR"}` {
		t.Errorf("Body snippet = %q", string(httpErr.Body))
	}
}

func TestAmfClient_SendCallback_4xxNotRetryable(t *testing.T) {
	mockAMF := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer mockAMF.Close()

	client := NewAmfClient()
	client.Client.Transport = http.DefaultTransport
	err := client.SendCallback(context.Background(), mockAMF.URL, nil)

	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("expected *HTTPError, got %T", err)
	}
	if httpErr.IsRetryable() {
		t.Error("400 must NOT be retryable; failover loop would spin forever")
	}
}

func TestNewAmfClientWithConfig_PartialMTLS_Fails(t *testing.T) {
	// Cert without key — operator forgot half the config. We MUST fail
	// loudly; silently downgrading to another mode would let outbound traffic
	// to a peer expecting mTLS fail with confusing TLS handshake errors.
	// (A CA alone is TLS without a client certificate: transport_test.go.)
	cases := []AmfClientConfig{
		{TLSCertFile: "/tmp/cert"},                    // cert only
		{TLSKeyFile: "/tmp/key"},                      // key only
		{TLSCertFile: "/tmp/c", TLSKeyFile: "/tmp/k"}, // missing CA
		{TLSCertFile: "/tmp/c", TLSCAFile: "/tmp/ca"}, // cert and CA, no key
		{TLSKeyFile: "/tmp/k", TLSCAFile: "/tmp/ca"},  // key and CA, no cert
	}
	for i, c := range cases {
		if _, err := NewAmfClientWithConfig(c); err == nil {
			t.Errorf("case %d: partial mTLS config %+v should fail", i, c)
		}
	}
}

func TestNewAmfClientWithConfig_NoMTLS_Plaintext(t *testing.T) {
	// All three empty → no error, h2c plaintext mode.
	c, err := NewAmfClientWithConfig(DefaultAmfClientConfig())
	if err != nil {
		t.Fatalf("default config (no mTLS) must build: %v", err)
	}
	if c == nil {
		t.Fatal("nil client")
	}
}

func TestAmfClient_SendCallback_429IsRetryable(t *testing.T) {
	mockAMF := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer mockAMF.Close()

	client := NewAmfClient()
	client.Client.Transport = http.DefaultTransport
	err := client.SendCallback(context.Background(), mockAMF.URL, nil)

	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("expected *HTTPError, got %T", err)
	}
	if !httpErr.IsRetryable() {
		t.Error("429 must be retryable per RFC 9110")
	}
}

func TestAmfClient_SendCallback_MarshalError(t *testing.T) {

	client := NewAmfClient()

	// Using a channel as a payload which cannot be marshaled to JSON

	err := client.SendCallback(context.Background(), "http://localhost", make(chan int))

	if err == nil {

		t.Fatal("Expected marshal error, got nil")

	}

}

func TestAmfClient_SendCallback_InvalidURL(t *testing.T) {

	client := NewAmfClient()

	err := client.SendCallback(context.Background(), "http://invalid url", map[string]string{"a": "b"})

	if err == nil {

		t.Fatal("Expected request error, got nil")

	}

}

// Retry-After in both of its forms reaches the caller with the HTTPError (RFC 9110 clause
// 10.2.3); an absent, invalid or past value is 0.
func TestRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	for value, want := range map[string]time.Duration{
		"":                              0,
		"120":                           2 * time.Minute,
		" 7 ":                           7 * time.Second,
		"Mon, 19 Oct 2026 12:00:30 GMT": 30 * time.Second,
		"Mon, 19 Oct 2026 11:00:00 GMT": 0,
		"-5":                            0,
		"soon":                          0,
	} {
		h := http.Header{}
		if value != "" {
			h.Set("Retry-After", value)
		}
		if got := retryAfter(h, now); got != want {
			t.Errorf("Retry-After %q: %s, want %s", value, got, want)
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "3")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	client := NewAmfClient()
	client.Client.Transport = http.DefaultTransport
	var httpErr *HTTPError
	if err := client.SendCallback(context.Background(), srv.URL, map[string]int{}); !errors.As(err, &httpErr) || httpErr.RetryAfter != 3*time.Second {
		t.Errorf("SendCallback: %v, want an HTTPError with RetryAfter 3s", err)
	}
}
