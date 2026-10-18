// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package oauth

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Claims is the validated subset of an NRF-issued NF access token (TS 33.501
// §13.4.1.1 / TS 29.510 §6.3.5.2.4) that downstream code is allowed to trust.
// Anything outside this struct came from the wire and has not been checked.
type Claims struct {
	Issuer     string // iss   — NRF instance ID
	Subject    string // sub   — Consumer NF instance ID (UUID); used as rate-limit key
	Audience   string // aud   — first audience entry (this gateway's NF ID)
	Scope      string // scope — RFC 6749 space-separated; checked via HasScope
	NFType     string // producerNfType from `producerSnssaiList`/`scope`-adjacent claim, optional
	Thumbprint []byte // cnf.x5t#S256 — RFC 8705 cert thumbprint when present in token
}

// extractClaims pulls our typed view out of a jwt.Token. We deliberately do
// NOT mutate or revalidate here — jwt.Parse already enforced sig + exp + aud +
// required-claim, so this is pure projection.
func extractClaims(tok jwt.Token) (*Claims, error) {
	c := &Claims{
		Issuer:  tok.Issuer(),
		Subject: tok.Subject(),
	}

	if auds := tok.Audience(); len(auds) > 0 {
		c.Audience = auds[0]
	}

	if v, ok := tok.Get("scope"); ok {
		if s, ok := v.(string); ok {
			c.Scope = s
		}
	}

	// producerNfType is optional in TS 29.510 — present in some NRF dialects.
	if v, ok := tok.Get("producerNfType"); ok {
		if s, ok := v.(string); ok {
			c.NFType = s
		}
	}

	// RFC 8705 §3.1 confirmation method. Shape:
	//   "cnf": { "x5t#S256": "<base64url(SHA-256 of client cert DER)>" }
	// We accept the claim being absent (caller decides if that's fatal via
	// OAUTH_REQUIRE_CERT_BINDING). Malformed cnf (wrong shape, bad base64)
	// is fatal even in lax mode — it signals an issuer bug, not absence.
	if v, ok := tok.Get("cnf"); ok {
		tp, err := extractCnfThumbprint(v)
		if err != nil {
			return nil, fmt.Errorf("cnf claim malformed: %w", err)
		}
		c.Thumbprint = tp
	}

	return c, nil
}

// extractCnfThumbprint decodes the cnf.x5t#S256 confirmation per RFC 8705 §3.1.
// Returns nil bytes (no error) when cnf is present but x5t#S256 is absent —
// other confirmation methods exist (jkt, jwk) but we don't accept them yet.
func extractCnfThumbprint(cnf interface{}) ([]byte, error) {
	m, ok := cnf.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("expected JSON object, got %T", cnf)
	}
	raw, ok := m["x5t#S256"]
	if !ok {
		return nil, nil // cnf present but no cert thumbprint — caller treats as "unbound"
	}
	s, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("x5t#S256 must be string, got %T", raw)
	}
	// RFC 8705 §3.1 mandates base64url *without* padding.
	tp, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("x5t#S256 base64url decode: %w", err)
	}
	if len(tp) != sha256.Size {
		return nil, fmt.Errorf("x5t#S256 length %d, want %d (SHA-256)", len(tp), sha256.Size)
	}
	return tp, nil
}

// bindingFromCert is reserved for the mTLS rollout (next sequence step). It
// computes the SHA-256 thumbprint per RFC 8705 §3.1 so we can compare against
// the token's `cnf.x5t#S256` claim. Currently unused; keeping the symbol so
// the validator interface that consumes it is forward-compatible.
//
//nolint:unused // referenced once mTLS lands.
func bindingFromCert(cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, fmt.Errorf("nil certificate")
	}
	sum := sha256.Sum256(cert.Raw)
	return sum[:], nil
}
