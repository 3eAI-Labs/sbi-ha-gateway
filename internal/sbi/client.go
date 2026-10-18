// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package sbi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// HTTPError is returned when the target NF responded with a non-2xx status.
// Transport-level failures (DNS, dial, timeout, TLS) come back as plain
// errors — the absence of an HTTPError means "no response received". This
// distinction matters for the failover policy: we retry/failover on transport
// failure and 5xx/429, but not on 4xx (caller bug, retrying would loop).
type HTTPError struct {
	StatusCode int
	Body       []byte // truncated to maxErrorBodySnippet bytes
}

const maxErrorBodySnippet = 512

func (e *HTTPError) Error() string {
	if len(e.Body) == 0 {
		return fmt.Sprintf("sbi: HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("sbi: HTTP %d: %s", e.StatusCode, string(e.Body))
}

// IsRetryable reports whether the failure justifies a retry against the same
// endpoint or a failover to an alternate. 5xx and 429 are retryable per
// RFC 9110; 4xx is the caller's fault and looping wastes budget.
func (e *HTTPError) IsRetryable() bool {
	return e.StatusCode >= 500 || e.StatusCode == http.StatusTooManyRequests
}

// AmfClientConfig contains configuration for AmfClient
type AmfClientConfig struct {
	Timeout         time.Duration // Request timeout
	ReadIdleTimeout time.Duration // Connection idle timeout before health check
	PingTimeout     time.Duration // Ping timeout for connection health check

	// mTLS — outbound client-side cert presentation per TS 33.310. When
	// any of the three is set the others must be too; the loader fails
	// fast at NewAmfClientWithConfig time. Leaving them empty falls back
	// to plaintext h2c (internal-mesh default).
	TLSCertFile string // client cert this gateway presents
	TLSKeyFile  string // matching key
	TLSCAFile   string // CAs trusted to sign peer (target NF) certs
}

// DefaultAmfClientConfig returns production-ready defaults
func DefaultAmfClientConfig() AmfClientConfig {
	return AmfClientConfig{
		Timeout:         5 * time.Second,
		ReadIdleTimeout: 30 * time.Second, // Check idle connections after 30s
		PingTimeout:     5 * time.Second,  // 5s to respond to ping
	}
}

// AmfClient sends callbacks to 5G Core NFs
type AmfClient struct {
	Client *http.Client
}

// NewAmfClient creates a new client with default configuration (no mTLS,
// h2c only). Production deployments should use NewAmfClientWithConfig and
// supply TLSCert/Key/CA paths.
func NewAmfClient() *AmfClient {
	c, _ := NewAmfClientWithConfig(DefaultAmfClientConfig())
	return c
}

// NewAmfClientWithConfig creates a new client with custom configuration.
// Returns an error when mTLS is partially configured (e.g., cert without key).
func NewAmfClientWithConfig(cfg AmfClientConfig) (*AmfClient, error) {
	tlsCfg, err := buildOutboundTLS(cfg)
	if err != nil {
		return nil, err
	}

	// HTTP/2 only. Without mTLS: unencrypted HTTP/2 with prior knowledge (h2c) to
	// http:// URIs. With mTLS: HTTP/2 over TLS to https:// URIs only — an http:// URI
	// fails rather than receiving the notification in cleartext.
	var protocols http.Protocols
	if tlsCfg == nil {
		protocols.SetUnencryptedHTTP2(true)
	} else {
		protocols.SetHTTP2(true)
	}
	t := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: cfg.Timeout}).DialContext,
		TLSClientConfig:     tlsCfg,
		TLSHandshakeTimeout: cfg.Timeout,
		Protocols:           &protocols,
		HTTP2: &http.HTTP2Config{
			SendPingTimeout: cfg.ReadIdleTimeout,
			PingTimeout:     cfg.PingTimeout,
		},
	}

	return &AmfClient{
		Client: &http.Client{
			Transport: t,
			Timeout:   cfg.Timeout,
		},
	}, nil
}

// buildOutboundTLS returns a *tls.Config when mTLS is fully configured,
// nil when no mTLS fields are set. Partial configuration is fatal —
// "had cert but no key" silently falls back to plaintext otherwise, and
// outbound traffic to a peer expecting mTLS would fail in opaque ways.
func buildOutboundTLS(cfg AmfClientConfig) (*tls.Config, error) {
	none := cfg.TLSCertFile == "" && cfg.TLSKeyFile == "" && cfg.TLSCAFile == ""
	if none {
		return nil, nil
	}
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" || cfg.TLSCAFile == "" {
		return nil, fmt.Errorf("sbi: mTLS partially configured (cert=%q key=%q ca=%q); set all three or none",
			cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSCAFile)
	}
	leaf, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("sbi: load client keypair: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.TLSCAFile)
	if err != nil {
		return nil, fmt.Errorf("sbi: read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("sbi: no PEM certs found in %s", cfg.TLSCAFile)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{leaf},
		RootCAs:      pool,
	}, nil
}

// SendCallback POSTs payload as JSON to uri. Returns nil on 2xx, *HTTPError
// on >=400 (with status + truncated body), or a plain error on transport
// failures. Callers wanting failover semantics should use errors.As to test
// for *HTTPError.IsRetryable().
func (c *AmfClient) SendCallback(ctx context.Context, uri string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("create request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		// Read up to maxErrorBodySnippet for ProblemDetails diagnostics
		// without unbounded memory if the peer streams a huge error body.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySnippet))
		return &HTTPError{StatusCode: resp.StatusCode, Body: snippet}
	}

	return nil
}
