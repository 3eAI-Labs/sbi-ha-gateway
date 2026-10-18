// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// signWithCnf mints a token whose `cnf` claim binds it to the given thumbprint.
func signWithCnf(t *testing.T, iss *testIssuer, sub, aud, scope string, thumbprint []byte) string {
	t.Helper()
	tok, _ := jwt.NewBuilder().
		Issuer("nrf.test").
		Subject(sub).
		Audience([]string{aud}).
		Expiration(time.Now().Add(5 * time.Minute)).
		Build()
	_ = tok.Set("scope", scope)
	if thumbprint != nil {
		_ = tok.Set("cnf", map[string]interface{}{
			"x5t#S256": base64.RawURLEncoding.EncodeToString(thumbprint),
		})
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(iss.alg, iss.priv))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func newValidatorRequiringBinding(t *testing.T, set jwk.Set, audience string, require bool) Validator {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "jwks.json")
	buf, _ := json.Marshal(set)
	_ = os.WriteFile(path, buf, 0o600)

	v, err := New(context.Background(), Config{
		JWKS:               JWKSConfig{FilePath: path},
		Audience:           audience,
		RequireCertBinding: require,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestBinding_CnfMatchesPeerCert(t *testing.T) {
	iss := newRSAIssuer(t, "k1")
	v := newValidatorRequiringBinding(t, iss.publicSet, "amf.local", true)

	certBytes := []byte("fake cert DER")
	tp := sha256.Sum256(certBytes)

	tok := signWithCnf(t, iss, "amf-1", "amf.local", "nausf-auth", tp[:])
	if _, err := v.Validate(context.Background(), tok, tp[:]); err != nil {
		t.Fatalf("matched cert binding should validate; got %v", err)
	}
}

func TestBinding_CnfMismatch_Rejected(t *testing.T) {
	iss := newRSAIssuer(t, "k1")
	v := newValidatorRequiringBinding(t, iss.publicSet, "amf.local", false)

	boundCert := sha256.Sum256([]byte("legitimate cert"))
	attackerCert := sha256.Sum256([]byte("attacker's cert"))

	// Token bound to legitimate cert; presented over a TLS session with
	// the attacker's cert. This is the canonical token-replay scenario
	// RFC 8705 was designed to defeat.
	tok := signWithCnf(t, iss, "amf-1", "amf.local", "nausf-auth", boundCert[:])
	_, err := v.Validate(context.Background(), tok, attackerCert[:])
	mustReason(t, err, ReasonCnfMismatch)
}

func TestBinding_CnfPresentButNoPeerCert_Rejected(t *testing.T) {
	iss := newRSAIssuer(t, "k1")
	v := newValidatorRequiringBinding(t, iss.publicSet, "amf.local", false)

	cert := sha256.Sum256([]byte("any cert"))
	tok := signWithCnf(t, iss, "amf-1", "amf.local", "nausf-auth", cert[:])
	// Caller forgot to thread the peer cert in (or the connection was
	// plaintext). Token carries cnf — must reject.
	_, err := v.Validate(context.Background(), tok, nil)
	mustReason(t, err, ReasonCnfNoCert)
}

func TestBinding_LaxMode_AcceptsUnboundToken(t *testing.T) {
	iss := newRSAIssuer(t, "k1")
	v := newValidatorRequiringBinding(t, iss.publicSet, "amf.local", false)

	tok := signWithCnf(t, iss, "amf-1", "amf.local", "nausf-auth", nil) // no cnf
	if _, err := v.Validate(context.Background(), tok, nil); err != nil {
		t.Fatalf("lax mode should accept unbound token; got %v", err)
	}
}

func TestBinding_StrictMode_RejectsUnboundToken(t *testing.T) {
	iss := newRSAIssuer(t, "k1")
	v := newValidatorRequiringBinding(t, iss.publicSet, "amf.local", true)

	tok := signWithCnf(t, iss, "amf-1", "amf.local", "nausf-auth", nil) // no cnf
	_, err := v.Validate(context.Background(), tok, nil)
	mustReason(t, err, ReasonCnfMissing)
}

func TestBinding_MalformedCnf_TokenRejected(t *testing.T) {
	iss := newRSAIssuer(t, "k1")
	v := newValidatorRequiringBinding(t, iss.publicSet, "amf.local", false)

	// cnf with wrong-length x5t#S256 (16 bytes instead of 32).
	bad := make([]byte, 16)
	tok := signWithCnf(t, iss, "amf-1", "amf.local", "nausf-auth", bad)
	if _, err := v.Validate(context.Background(), tok, nil); err == nil {
		t.Fatal("malformed cnf must reject the token in any mode")
	}
}

func TestBinding_CacheKeyIncludesPeerThumbprint(t *testing.T) {
	// Bind token to certA, validate ok with certA → cache hit.
	// Then reuse the SAME token with certB → must NOT short-circuit
	// to the cached "ok" — the cache key includes the peer thumbprint.
	iss := newRSAIssuer(t, "k1")
	v := newValidatorRequiringBinding(t, iss.publicSet, "amf.local", false)

	tpA := sha256.Sum256([]byte("certA"))
	tpB := sha256.Sum256([]byte("certB"))
	tok := signWithCnf(t, iss, "amf-1", "amf.local", "nausf-auth", tpA[:])

	if _, err := v.Validate(context.Background(), tok, tpA[:]); err != nil {
		t.Fatalf("first validate should succeed: %v", err)
	}
	// Same token, different cert. Cache must not hide the mismatch.
	_, err := v.Validate(context.Background(), tok, tpB[:])
	mustReason(t, err, ReasonCnfMismatch)
}

// ECDSA-signed counterpart to confirm cnf works with both algorithms.
func TestBinding_WorksWithES256(t *testing.T) {
	iss := newECIssuer(t, "k-ec1")
	v := newValidatorRequiringBinding(t, iss.publicSet, "amf.local", true)

	cert := sha256.Sum256([]byte("ec cert"))
	tok := signWithCnf(t, iss, "amf-ec", "amf.local", "nausf-auth", cert[:])
	if _, err := v.Validate(context.Background(), tok, cert[:]); err != nil {
		t.Fatalf("ES256 + cnf should validate: %v", err)
	}

	// Sanity: jwa.RS256 / jwa.ES256 still in allowlist.
	for _, alg := range []jwa.SignatureAlgorithm{jwa.RS256, jwa.ES256} {
		if _, ok := allowedAlgs[alg]; !ok {
			t.Errorf("%s missing from allowlist", alg)
		}
	}
}
