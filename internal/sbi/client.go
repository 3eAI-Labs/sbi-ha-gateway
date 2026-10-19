// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package sbi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"strconv"
	"strings"
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
	// RetryAfter is the response's Retry-After (RFC 9110 clause 10.2.3), 0 without one: the
	// gateway must not call the endpoint again before it (TS 29.500 clause 6.4).
	RetryAfter time.Duration
}

const maxErrorBodySnippet = 512

func (e *HTTPError) Error() string {
	if len(e.Body) == 0 {
		return fmt.Sprintf("sbi: HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("sbi: HTTP %d: %s", e.StatusCode, string(e.Body))
}

// retryAfter reads Retry-After, delay-seconds or an HTTP-date; 0 when it is absent, invalid
// or already past.
func retryAfter(h http.Header, now time.Time) time.Duration {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0
	}
	if secs, err := strconv.ParseUint(v, 10, 32); err == nil {
		return time.Duration(secs) * time.Second
	}
	if at, err := http.ParseTime(v); err == nil && at.After(now) {
		return at.Sub(now)
	}
	return 0
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

	// Outbound TLS (TS 33.310). TLSCAFile alone: TLS with that trust anchor and no client
	// certificate. With a client certificate (TLSCertFile and TLSKeyFile, always together)
	// TLSCAFile is required too. Any of them set: https:// URIs only. None: https:// URIs
	// against the system roots, and http:// URIs as h2c. Anything else fails at
	// NewAmfClientWithConfig.
	TLSCertFile string // client cert this gateway presents
	TLSKeyFile  string // matching key
	TLSCAFile   string // CAs trusted to sign peer (target NF) certs

	// Destinations limits which hosts calls may reach, checked on the dialled address;
	// nil: no limit (tests, tools). The gateway always sets it.
	Destinations *Destinations
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

	// HTTP/2 only (TS 29.500 clause 5.2.1): https:// URIs get HTTP/2 over TLS, never
	// HTTP/1.1. http:// URIs get HTTP/2 with prior knowledge (h2c) only when no outbound TLS
	// is configured; with it, they fail rather than receiving the notification in cleartext.
	var protocols http.Protocols
	protocols.SetHTTP2(true)
	if tlsCfg == nil {
		protocols.SetUnencryptedHTTP2(true)
	}
	dial := (&net.Dialer{Timeout: cfg.Timeout}).DialContext
	if cfg.Destinations != nil {
		dial = cfg.Destinations.DialContext(dial)
	}
	t := &http.Transport{
		DialContext:         dial,
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

// buildOutboundTLS returns the outbound TLS configuration, nil when none is set. A client
// certificate without its key (or the reverse), or without a CA, is fatal: "had cert but no
// key" would otherwise fall back to another mode, and traffic to a peer expecting mTLS would
// fail in opaque ways.
// OutboundTLS is the gateway's TLS client configuration towards 5GC peers from the
// MTLS_OUTBOUND_* files: nil without them (system roots, no certificate), an error when they
// are partial.
func OutboundTLS(certFile, keyFile, caFile string) (*tls.Config, error) {
	return buildOutboundTLS(AmfClientConfig{TLSCertFile: certFile, TLSKeyFile: keyFile, TLSCAFile: caFile})
}

func buildOutboundTLS(cfg AmfClientConfig) (*tls.Config, error) {
	if cfg.TLSCertFile == "" && cfg.TLSKeyFile == "" && cfg.TLSCAFile == "" {
		return nil, nil
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") || cfg.TLSCAFile == "" {
		return nil, fmt.Errorf("sbi: outbound TLS partially configured (cert=%q key=%q ca=%q); "+
			"set the CA, the CA with a certificate and its key, or none",
			cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSCAFile)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if cfg.TLSCertFile != "" {
		leaf, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("sbi: load client keypair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{leaf}
	}
	caPEM, err := os.ReadFile(cfg.TLSCAFile)
	if err != nil {
		return nil, fmt.Errorf("sbi: read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("sbi: no PEM certs found in %s", cfg.TLSCAFile)
	}
	tlsCfg.RootCAs = pool
	return tlsCfg, nil
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
		return &HTTPError{StatusCode: resp.StatusCode, Body: snippet, RetryAfter: retryAfter(resp.Header, time.Now())}
	}

	return nil
}

// maxMultipartResponseBytes bounds a multipart response: an SMS delivery report is a few
// hundred bytes.
const maxMultipartResponseBytes = 64 << 10

// Multipart is one JSON part and one binary part of a multipart/related message (TS 29.500
// clause 6.1.2.2.2; TS 29.540 clause 6.1.2.4): the JSON part is the root and refers to the
// binary part by its Content-ID.
type Multipart struct {
	JSON       []byte
	Binary     []byte
	BinaryType string // e.g. "application/vnd.3gpp.sms"
	ContentID  string
}

// PostMultipart POSTs m to uri as multipart/related and returns the response's parts: a
// 2xx with a multipart/related body is parsed into a Multipart (JSON part first, the binary
// part found by any other content type), a 2xx with another body gives its bytes as JSON.
// Errors are as SendCallback's: *HTTPError for >= 400, a plain error for transport failures.
func (c *AmfClient) PostMultipart(ctx context.Context, uri string, m Multipart) (*Multipart, error) {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	jsonPart, err := w.CreatePart(textproto.MIMEHeader{"Content-Type": {"application/json"}})
	if err == nil {
		_, err = jsonPart.Write(m.JSON)
	}
	if err == nil {
		var binPart io.Writer
		binPart, err = w.CreatePart(textproto.MIMEHeader{
			"Content-Type": {m.BinaryType},
			"Content-Id":   {m.ContentID},
		})
		if err == nil {
			_, err = binPart.Write(m.Binary)
		}
	}
	if err == nil {
		err = w.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("build multipart: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, &body)
	if err != nil {
		return nil, fmt.Errorf("create request failed: %w", err)
	}
	req.Header.Set("Content-Type", mime.FormatMediaType("multipart/related",
		map[string]string{"boundary": w.Boundary(), "type": "application/json"}))

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySnippet))
		return nil, &HTTPError{StatusCode: resp.StatusCode, Body: snippet, RetryAfter: retryAfter(resp.Header, time.Now())}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxMultipartResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	mediaType, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/related" {
		return &Multipart{JSON: data}, nil
	}
	return parseMultipart(data, params["boundary"])
}

// parseMultipart reads a multipart/related body: its first part is the JSON root, and the
// first other part not of type application/json is the binary part.
func parseMultipart(data []byte, boundary string) (*Multipart, error) {
	if boundary == "" {
		return nil, errors.New("multipart response without a boundary")
	}
	r := multipart.NewReader(bytes.NewReader(data), boundary)
	var out Multipart
	for i := 0; ; i++ {
		part, err := r.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read multipart response: %w", err)
		}
		content, err := io.ReadAll(part)
		if err != nil {
			return nil, fmt.Errorf("read multipart response: %w", err)
		}
		ct, _, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
		switch {
		case i == 0:
			out.JSON = content
		case out.Binary == nil && ct != "application/json":
			out.Binary, out.BinaryType, out.ContentID = content, ct, part.Header.Get("Content-Id")
		}
	}
	return &out, nil
}
