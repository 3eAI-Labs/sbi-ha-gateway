// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

// Package server: TLS configuration for the SBI listener.
//
// This file builds the *tls.Config for the inbound HTTP/2 server. Certificate
// loading for *outbound* calls lives in internal/sbi/client.go — the server
// and client sides have different trust requirements (server presents its
// cert + verifies clients via ClientCAs; client presents its cert + verifies
// server via system roots or pinned roots).
package server

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// ClientAuthMode controls whether peer certificates are required.
//
// "off"      — accept any client; no peer cert validation. Used in dev or
//
//	when running behind a service mesh that already enforces mTLS.
//
// "optional" — peer may present a cert; if it does, it must verify against
//
//	ClientCAs. Used during a phased mTLS rollout where some peers
//	haven't migrated yet.
//
// "require"  — peer MUST present a cert that verifies against ClientCAs.
//
//	The carrier-grade target state per TS 33.310.
type ClientAuthMode string

const (
	ClientAuthOff      ClientAuthMode = "off"
	ClientAuthOptional ClientAuthMode = "optional"
	ClientAuthRequire  ClientAuthMode = "require"
)

func (m ClientAuthMode) toTLS() (tls.ClientAuthType, error) {
	switch m {
	case ClientAuthOff, "":
		return tls.NoClientCert, nil
	case ClientAuthOptional:
		return tls.VerifyClientCertIfGiven, nil
	case ClientAuthRequire:
		return tls.RequireAndVerifyClientCert, nil
	default:
		return 0, fmt.Errorf("server: unknown MTLS_CLIENT_AUTH_MODE %q (want off/optional/require)", m)
	}
}

// TLSOptions bundles the inbound TLS surface.
type TLSOptions struct {
	CertFile       string         // server cert (required when TLS enabled)
	KeyFile        string         // server key  (required when TLS enabled)
	ClientCAFile   string         // PEM bundle of CAs trusted to sign peer certs (mTLS)
	ClientAuthMode ClientAuthMode // off / optional / require
}

// TLSEnabled reports whether server-side TLS is requested. Returning false
// means the listener falls back to h2c (cleartext HTTP/2) for internal mesh.
func (o TLSOptions) TLSEnabled() bool {
	return o.CertFile != "" && o.KeyFile != ""
}

// MTLSEnabled reports whether the peer-cert side of mTLS is requested.
// "Optional" and "require" both count as enabled — the difference is whether
// missing peer certs are accepted, not whether the trust chain is loaded.
func (o TLSOptions) MTLSEnabled() bool {
	return o.ClientCAFile != "" &&
		(o.ClientAuthMode == ClientAuthOptional || o.ClientAuthMode == ClientAuthRequire)
}

// BuildTLSConfig produces the *tls.Config to hand to http.Server. Returns
// (nil, nil) when TLS is not enabled — caller should fall back to h2c.
//
// Carrier-grade pins:
//   - MinVersion = TLS 1.3 (TS 33.210 §5.3.3 mandates ≥1.2; we go straight to 1.3).
//   - NextProtos = ["h2"] — gateway is HTTP/2 only on the SBI port.
//   - When ClientAuthMode is "require" but no CA file is set, the build fails
//     fast: silently downgrading to "no peer verification" would defeat mTLS.
//   - A certificate without its key, or the reverse, and client-certificate
//     settings without TLS fail too: each would otherwise serve cleartext h2c
//     to an operator who asked for TLS.
func BuildTLSConfig(o TLSOptions) (*tls.Config, error) {
	if (o.CertFile == "") != (o.KeyFile == "") {
		return nil, errors.New("server: TLS_CERT_FILE and TLS_KEY_FILE must be set together; with only one the SBI port would serve cleartext h2c")
	}
	authType, err := o.ClientAuthMode.toTLS()
	if err != nil {
		return nil, err
	}
	if !o.TLSEnabled() {
		if o.MTLSEnabled() {
			return nil, errors.New("server: MTLS_CLIENT_CA_FILE set but TLS disabled (TLS_CERT_FILE/TLS_KEY_FILE missing)")
		}
		if authType != tls.NoClientCert {
			return nil, fmt.Errorf("server: MTLS_CLIENT_AUTH_MODE=%s needs TLS (TLS_CERT_FILE/TLS_KEY_FILE missing); "+
				"a cleartext SBI port (ALLOW_PLAINTEXT_SBI) needs MTLS_CLIENT_AUTH_MODE=off", o.ClientAuthMode)
		}
		return nil, nil
	}

	// The certificate is loaded here, at start-up: one that cannot be read stops the gateway
	// before it listens, rather than failing the server afterwards.
	pair, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("server: load TLS_CERT_FILE/TLS_KEY_FILE: %w", err)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
		ClientAuth:   authType,
		Certificates: []tls.Certificate{pair},
	}

	if authType != tls.NoClientCert {
		if o.ClientCAFile == "" {
			return nil, fmt.Errorf("server: MTLS_CLIENT_AUTH_MODE=%s requires MTLS_CLIENT_CA_FILE", o.ClientAuthMode)
		}
		pool, err := loadCAPool(o.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("server: load client CA bundle: %w", err)
		}
		cfg.ClientCAs = pool
	}

	return cfg, nil
}

// loadCAPool reads a PEM bundle and returns an x509.CertPool. An empty bundle
// is a configuration error: it would create a pool that trusts nothing,
// which silently rejects every peer — appearing as "all clients fail mTLS"
// in production.
func loadCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path) // #nosec G304 -- MTLS_CLIENT_CA_FILE, set by the operator, never by a request
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no PEM certificates found in %s", path)
	}
	return pool, nil
}
