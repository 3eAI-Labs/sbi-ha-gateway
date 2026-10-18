// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Config is the validator's runtime config — flat on purpose so config.Load()
// can populate it from env without an intermediate mapper.
type Config struct {
	JWKS           JWKSConfig
	Audience       string        // expected aud claim — this gateway's NF instance ID
	ClockSkew      time.Duration // ± tolerance for exp/nbf/iat checks; default 30s
	ResultCacheTTL time.Duration // per-token positive cache TTL; 0 disables. Default 60s.

	// RequireCertBinding controls RFC 8705 §3 enforcement when the request
	// arrived without a cnf claim:
	//   false → unbound tokens accepted (warn-log path; default to allow
	//           pre-RFC-8705 NRF deployments)
	//   true  → unbound tokens rejected with ReasonCnfMissing
	// The presence of a cnf claim ALWAYS triggers binding verification —
	// this flag only controls behaviour when cnf is absent.
	RequireCertBinding bool
}

// Validator is the public surface used by the chi middleware. The interface
// exists so middleware tests can pass a fake without spinning up jwx.
type Validator interface {
	// Validate parses + verifies a Bearer token, enforces required claims,
	// and returns the trusted Claims projection. err is *ValidationError
	// with a typed Reason.
	//
	// peerCertThumbprint is the SHA-256 of the verified TLS peer cert (DER)
	// or nil when the request did not arrive over mTLS. The validator uses
	// it for RFC 8705 cert binding when the token carries a cnf claim
	// and/or RequireCertBinding is true.
	Validate(ctx context.Context, bearer string, peerCertThumbprint []byte) (*Claims, error)
}

// New builds a Validator from cfg. The returned validator is safe for
// concurrent use; it owns a background-refreshed JWKS cache when
// cfg.JWKS.NRFURL is set.
func New(ctx context.Context, cfg Config, log *slog.Logger) (Validator, error) {
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = 30 * time.Second
	}
	if cfg.ResultCacheTTL == 0 {
		cfg.ResultCacheTTL = 60 * time.Second
	}
	if cfg.Audience == "" {
		return nil, errors.New("oauth: Audience is required (set OAUTH_AUDIENCE)")
	}

	src, err := loadKeySource(ctx, cfg.JWKS, log)
	if err != nil {
		return nil, err
	}

	return &validator{
		src:                src,
		audience:           cfg.Audience,
		skew:               cfg.ClockSkew,
		resultTTL:          cfg.ResultCacheTTL,
		requireCertBinding: cfg.RequireCertBinding,
		results:            make(map[string]cachedResult),
	}, nil
}

type validator struct {
	src                keySource
	audience           string
	skew               time.Duration
	requireCertBinding bool

	// Per-token positive cache. A token from a hot caller hits this on
	// every request — without it, jwt.Parse re-runs RSA verify each time
	// and the validator becomes the load bottleneck. Negative results are
	// NOT cached because we want every retry to be re-evaluated against
	// the latest JWKS (e.g. after key rotation a previously-rejected
	// "unknown_kid" token might now verify).
	resultTTL time.Duration
	mu        sync.Mutex
	results   map[string]cachedResult
}

type cachedResult struct {
	claims *Claims
	expiry time.Time
}

func (v *validator) Validate(ctx context.Context, bearer string, peerCertThumbprint []byte) (*Claims, error) {
	bearer = strings.TrimSpace(bearer)
	if bearer == "" {
		return nil, newErr(ReasonMissingToken, nil)
	}

	// Binding the cache key to the peer cert thumbprint prevents a
	// cached "ok" result for token T (validated under cert A) from
	// short-circuiting a request presenting cert B. Without this, RFC 8705
	// enforcement could be bypassed by warming the cache with a legitimate
	// pairing then replaying with a different cert inside the TTL window.
	cacheKey := tokenFingerprint(bearer, peerCertThumbprint)
	if c, ok := v.cacheGet(cacheKey); ok {
		return c, nil
	}

	tok, err := jwt.Parse(
		[]byte(bearer),
		jwt.WithKeySet(
			v.src.keys(),
			jws.WithInferAlgorithmFromKey(false),
			jws.WithRequireKid(true),
		),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(v.skew),
		jwt.WithAudience(v.audience),
		jwt.WithRequiredClaim("sub"),
		jwt.WithRequiredClaim("iss"),
		jwt.WithRequiredClaim("scope"),
		jwt.WithRequiredClaim("exp"),
	)
	if err != nil {
		return nil, classifyParseErr(err)
	}

	claims, err := extractClaims(tok)
	if err != nil {
		return nil, newErr(ReasonMalformed, err)
	}
	if claims.Subject == "" {
		return nil, newErr(ReasonMissingClaim, errors.New("sub is empty"))
	}

	if err := v.checkCertBinding(claims, peerCertThumbprint); err != nil {
		return nil, err
	}

	v.cachePut(cacheKey, claims, tok)
	return claims, nil
}

// checkCertBinding enforces RFC 8705 §3 confirmation. The four states:
//
//	cnf present, peer cert present  → must match (mismatch → ReasonCnfMismatch)
//	cnf present, peer cert absent   → ReasonCnfNoCert (token bound to a cert
//	                                  the connection didn't present — replay)
//	cnf absent,  peer cert present  → unbound; allowed (token wasn't issued
//	                                  with binding, gateway is more strict
//	                                  than NRF — that's fine)
//	cnf absent,  peer cert absent   → unbound; allowed iff RequireCertBinding
//	                                  is false. Strict mode rejects.
func (v *validator) checkCertBinding(claims *Claims, peerCertThumbprint []byte) error {
	if len(claims.Thumbprint) == 0 {
		// Token has no cnf.
		if v.requireCertBinding {
			return newErr(ReasonCnfMissing, errors.New("OAUTH_REQUIRE_CERT_BINDING is true but token has no cnf claim"))
		}
		return nil
	}
	// Token has cnf — peer cert MUST be present and match.
	if len(peerCertThumbprint) == 0 {
		return newErr(ReasonCnfNoCert, errors.New("token is cert-bound but request had no peer cert"))
	}
	if !bytesEqualConstantTime(claims.Thumbprint, peerCertThumbprint) {
		return newErr(ReasonCnfMismatch, errors.New("peer cert thumbprint does not match cnf.x5t#S256"))
	}
	return nil
}

// bytesEqualConstantTime is subtle.ConstantTimeCompare's result-as-bool
// wrapper. Constant-time matters here even though both sides are public
// hashes — a timing oracle on a thumbprint comparison would let an attacker
// learn how many leading bytes matched while iterating crafted certs.
func bytesEqualConstantTime(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func (v *validator) cacheGet(key string) (*Claims, bool) {
	if v.resultTTL == 0 {
		return nil, false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	c, ok := v.results[key]
	if !ok || time.Now().After(c.expiry) {
		if ok {
			delete(v.results, key)
		}
		return nil, false
	}
	return c.claims, true
}

func (v *validator) cachePut(key string, claims *Claims, tok jwt.Token) {
	if v.resultTTL == 0 {
		return
	}
	// Cap TTL to min(resultTTL, token.exp - now). A 60s positive cache for
	// a token that expires in 5s would happily keep accepting it for 55s
	// past its real expiry — exactly the kind of subtle hole an audit
	// finds first.
	expiry := time.Now().Add(v.resultTTL)
	if exp := tok.Expiration(); !exp.IsZero() && exp.Before(expiry) {
		expiry = exp
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.results[key] = cachedResult{claims: claims, expiry: expiry}
	// Cheap opportunistic GC: if the map grew past 1024 entries, sweep the
	// expired ones. Avoids unbounded growth without a goroutine to wire
	// into shutdown — same shape the rate limiter uses.
	if len(v.results) > 1024 {
		now := time.Now()
		for k, c := range v.results {
			if now.After(c.expiry) {
				delete(v.results, k)
			}
		}
	}
}

// tokenFingerprint hashes the bearer (plus optional peer cert thumbprint)
// so the cache key is fixed-size and we never log the raw token by accident
// if the map is dumped. Including the cert thumbprint partitions the cache
// per (token, cert) pair — see Validate() for why.
func tokenFingerprint(bearer string, peerCertThumbprint []byte) string {
	h := sha256.New()
	h.Write([]byte(bearer))
	if len(peerCertThumbprint) > 0 {
		h.Write([]byte{0x00}) // domain separator: keeps "bearer|cert" ≠ "bearercert"
		h.Write(peerCertThumbprint)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// classifyParseErr inspects jwx's wrapped error and produces a typed reason.
// jwx does not expose stable sentinel errors for every case, so we fall back
// to substring matching for the cases that need distinct telemetry. The
// strings checked here come from jwt/options.go and jws/verify.go in v2.1.6;
// if jwx changes them, the metric label degrades to "malformed" but the
// security posture (reject) stays correct — fail-closed.
func classifyParseErr(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, `"exp" not satisfied`),
		strings.Contains(msg, `token is expired`):
		return newErr(ReasonExpired, err)
	case strings.Contains(msg, `"nbf" not satisfied`),
		strings.Contains(msg, `not yet valid`):
		return newErr(ReasonNotYetValid, err)
	case strings.Contains(msg, `"aud" not satisfied`):
		return newErr(ReasonWrongAudience, err)
	case strings.Contains(msg, `required claim`),
		strings.Contains(msg, `not found`):
		return newErr(ReasonMissingClaim, err)
	case strings.Contains(msg, `find key`),
		strings.Contains(msg, `key ID`),
		strings.Contains(msg, `kid`):
		return newErr(ReasonUnknownKid, err)
	case strings.Contains(msg, `failed to verify`),
		strings.Contains(msg, `signature`),
		strings.Contains(msg, `key provider`):
		return newErr(ReasonInvalidSig, err)
	case strings.Contains(msg, `algorithm`):
		return newErr(ReasonDisallowedAlg, err)
	default:
		return newErr(ReasonMalformed, err)
	}
}
