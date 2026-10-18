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
	// loudly; silently downgrading to plaintext would let outbound traffic
	// to a peer expecting mTLS fail with confusing TLS handshake errors.
	cases := []AmfClientConfig{
		{TLSCertFile: "/tmp/cert"},                    // cert only
		{TLSKeyFile: "/tmp/key"},                      // key only
		{TLSCAFile: "/tmp/ca"},                        // ca only
		{TLSCertFile: "/tmp/c", TLSKeyFile: "/tmp/k"}, // missing CA
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
