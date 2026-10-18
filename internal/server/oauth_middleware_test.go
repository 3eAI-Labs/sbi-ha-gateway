// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/models"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/oauth"
	tlsgen "github.com/3eAI-Labs/sbi-ha-gateway/internal/testutil/tlsgen"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// mintTokenWithCnf is mintToken with an RFC 8705 confirmation method.
func mintTokenWithCnf(t *testing.T, signer jwk.Key, sub, aud, scope string, certThumbprint []byte) string {
	t.Helper()
	tok, _ := jwt.NewBuilder().
		Issuer("nrf.test").
		Subject(sub).
		Audience([]string{aud}).
		Expiration(time.Now().Add(5 * time.Minute)).
		Build()
	_ = tok.Set("scope", scope)
	_ = tok.Set("cnf", map[string]interface{}{
		"x5t#S256": base64.RawURLEncoding.EncodeToString(certThumbprint),
	})
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, signer))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

// genTestLeaf returns a freshly-minted cert + its thumbprint + DER bytes,
// suitable for stuffing into req.TLS.PeerCertificates.
func genTestLeaf(t *testing.T) (*x509.Certificate, []byte, []byte) {
	t.Helper()
	ca := tlsgen.NewCA(t)
	uri, _ := url.Parse("urn:5g:nf-instance-id:test-uuid")
	leaf := ca.Sign(t, tlsgen.LeafSpec{
		CommonName: "test-peer",
		URIs:       []*url.URL{uri},
		IsClient:   true,
	})
	tp := sha256.Sum256(leaf.Cert.Raw)
	return leaf.Cert, tp[:], leaf.Cert.Raw
}

// mintTestValidator returns (validator, signer, kid). The signer can be used
// to mint tokens for individual cases. Network-free, file-backed JWKS.
func mintTestValidator(t *testing.T, audience string) (oauth.Validator, jwk.Key, string) {
	t.Helper()
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := jwk.FromRaw(rsaPriv)
	_ = priv.Set(jwk.KeyIDKey, "k1")
	_ = priv.Set(jwk.AlgorithmKey, jwa.RS256)
	pub, _ := priv.PublicKey()
	set := jwk.NewSet()
	_ = set.AddKey(pub)

	dir := t.TempDir()
	path := filepath.Join(dir, "jwks.json")
	buf, _ := json.Marshal(set)
	_ = os.WriteFile(path, buf, 0o600)

	v, err := oauth.New(context.Background(), oauth.Config{
		JWKS:     oauth.JWKSConfig{FilePath: path},
		Audience: audience,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return v, priv, "k1"
}

func mintToken(t *testing.T, signer jwk.Key, sub, aud, scope string, exp time.Time) string {
	t.Helper()
	if exp.IsZero() {
		exp = time.Now().Add(5 * time.Minute)
	}
	tok, _ := jwt.NewBuilder().
		Issuer("nrf.test").
		Subject(sub).
		Audience([]string{aud}).
		Expiration(exp).
		Build()
	_ = tok.Set("scope", scope)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, signer))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

// captureSubHandler grabs the sub claim out of the request context so the
// rate limiter integration test (next file) can verify the middleware injected it.
func captureSubHandler(out *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*out = NFSubjectFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
}

func TestOAuthMiddleware_HappyPath(t *testing.T) {
	v, signer, _ := mintTestValidator(t, "amf.local")
	var capturedSub string
	h := OAuthMiddleware(v)(captureSubHandler(&capturedSub))

	tok := mintToken(t, signer, "AMF-uuid-1", "amf.local", "nausf-auth", time.Time{})
	req := httptest.NewRequest("GET", "/nausf-auth/v1/ue-authentications", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if capturedSub != "AMF-uuid-1" {
		t.Errorf("sub injected into context = %q", capturedSub)
	}
}

func TestOAuthMiddleware_PublicPathBypass(t *testing.T) {
	v, _, _ := mintTestValidator(t, "amf.local")
	h := OAuthMiddleware(v)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/livez", nil) // no Authorization header
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("public path should bypass; got %d", rec.Code)
	}
}

func TestOAuthMiddleware_NilValidatorPasses(t *testing.T) {
	// OAUTH_DISABLED=true scenario: middleware constructed with nil
	// validator must be a transparent passthrough.
	h := OAuthMiddleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/nausf-auth/v1/x", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("nil validator should pass; got %d", rec.Code)
	}
}

func TestOAuthMiddleware_MissingBearer(t *testing.T) {
	v, _, _ := mintTestValidator(t, "amf.local")
	h := OAuthMiddleware(v)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest("GET", "/nausf-auth/v1/x", nil) // no Authorization
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got == "" {
		t.Errorf("WWW-Authenticate must be set on 401 (RFC 6750 §3); got empty")
	}
	var pd models.ProblemDetails
	if err := json.NewDecoder(rec.Body).Decode(&pd); err != nil {
		t.Fatalf("body not problem+json: %v", err)
	}
	if pd.Status != http.StatusUnauthorized {
		t.Errorf("ProblemDetails.status = %d", pd.Status)
	}
}

func TestOAuthMiddleware_InsufficientScope(t *testing.T) {
	v, signer, _ := mintTestValidator(t, "amf.local")
	h := OAuthMiddleware(v)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	// Token only has nudm-sdm but request hits nausf-auth.
	tok := mintToken(t, signer, "AMF-uuid-1", "amf.local", "nudm-sdm", time.Time{})
	req := httptest.NewRequest("GET", "/nausf-auth/v1/ue-authentications", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	var pd models.ProblemDetails
	_ = json.NewDecoder(rec.Body).Decode(&pd)
	if pd.Cause != "INSUFFICIENT_SCOPES" {
		t.Errorf("cause = %q, want INSUFFICIENT_SCOPES", pd.Cause)
	}
}

func TestOAuthMiddleware_ExpiredToken(t *testing.T) {
	v, signer, _ := mintTestValidator(t, "amf.local")
	h := OAuthMiddleware(v)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	tok := mintToken(t, signer, "x", "amf.local", "nausf-auth", time.Now().Add(-2*time.Minute))
	req := httptest.NewRequest("GET", "/nausf-auth/v1/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	var pd models.ProblemDetails
	_ = json.NewDecoder(rec.Body).Decode(&pd)
	if pd.Cause != "TOKEN_EXPIRED" {
		t.Errorf("cause = %q, want TOKEN_EXPIRED", pd.Cause)
	}
}

// End-to-end: PeerIdentityMiddleware → OAuthMiddleware → handler. Verifies
// that a cert-bound token presented over the cert it was bound to passes,
// and the same token over a different cert is rejected with TOKEN_BINDING_FAILED.
func TestOAuthMiddleware_RFC8705_BindingMismatchRejected(t *testing.T) {
	v, signer, _ := mintTestValidator(t, "amf.local")

	// Token bound to certA's thumbprint.
	tpA := sha256.Sum256([]byte("certA DER"))
	tok := mintTokenWithCnf(t, signer, "amf-1", "amf.local", "nausf-auth", tpA[:])

	// Build the chain in the same order as router.go: peer identity then OAuth.
	chain := PeerIdentityMiddleware(OAuthMiddleware(v)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	// Present the token over certB — replay scenario.
	certBPEM, _, _ := genTestLeaf(t)
	req := httptest.NewRequest("GET", "/nausf-auth/v1/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certBPEM}}

	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for cnf mismatch; got %d body=%s", rec.Code, rec.Body.String())
	}
	var pd struct{ Cause string }
	_ = json.NewDecoder(rec.Body).Decode(&pd)
	if pd.Cause != "TOKEN_BINDING_FAILED" {
		t.Errorf("cause = %q, want TOKEN_BINDING_FAILED", pd.Cause)
	}
}

func TestOAuthMiddleware_RFC8705_BindingMatchAccepted(t *testing.T) {
	v, signer, _ := mintTestValidator(t, "amf.local")

	cert, _, _ := genTestLeaf(t)
	tp := sha256.Sum256(cert.Raw)

	tok := mintTokenWithCnf(t, signer, "amf-1", "amf.local", "nausf-auth", tp[:])
	chain := PeerIdentityMiddleware(OAuthMiddleware(v)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest("GET", "/nausf-auth/v1/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200; got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestExtractBearer(t *testing.T) {
	cases := []struct {
		in      string
		wantTok string
		wantOk  bool
	}{
		{"", "", false},
		{"Basic abc", "", false},
		{"Bearer ", "", false},
		{"Bearer ", "", false},
		{"Bearer abc.def.ghi", "abc.def.ghi", true},
		{"Bearer   abc.def.ghi   ", "abc.def.ghi", true},
		{"bearer abc", "", false}, // lowercase b rejected
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, ok := extractBearer(c.in)
			if got != c.wantTok || ok != c.wantOk {
				t.Errorf("extractBearer(%q) = (%q, %v), want (%q, %v)",
					c.in, got, ok, c.wantTok, c.wantOk)
			}
		})
	}
}
