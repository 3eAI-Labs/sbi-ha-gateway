// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// testIssuer bundles a key pair and helpers for minting test tokens. Tests
// stay independent of network state — every test gets its own issuer with a
// fresh key, so cache pollution between tests is impossible.
type testIssuer struct {
	priv      jwk.Key
	pub       jwk.Key
	publicSet jwk.Set
	alg       jwa.SignatureAlgorithm
	kid       string
}

func newRSAIssuer(t *testing.T, kid string) *testIssuer {
	t.Helper()
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return buildIssuer(t, rsaPriv, jwa.RS256, kid)
}

func newECIssuer(t *testing.T, kid string) *testIssuer {
	t.Helper()
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return buildIssuer(t, ecPriv, jwa.ES256, kid)
}

func buildIssuer(t *testing.T, raw any, alg jwa.SignatureAlgorithm, kid string) *testIssuer {
	t.Helper()
	priv, err := jwk.FromRaw(raw)
	if err != nil {
		t.Fatalf("jwk.FromRaw: %v", err)
	}
	if err := priv.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatal(err)
	}
	if err := priv.Set(jwk.AlgorithmKey, alg); err != nil {
		t.Fatal(err)
	}
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		t.Fatal(err)
	}
	return &testIssuer{priv: priv, pub: pub, publicSet: set, alg: alg, kid: kid}
}

type tokenOpts struct {
	sub       string
	aud       string
	scope     string
	exp       time.Time
	nbf       time.Time
	skipExp   bool
	skipScope bool
	skipAud   bool
	skipSub   bool
}

func (i *testIssuer) sign(t *testing.T, o tokenOpts) string {
	t.Helper()
	b := jwt.NewBuilder().
		Issuer("nrf.test")
	if !o.skipSub {
		b = b.Subject(o.sub)
	}
	if !o.skipAud {
		b = b.Audience([]string{o.aud})
	}
	if !o.skipExp {
		exp := o.exp
		if exp.IsZero() {
			exp = time.Now().Add(5 * time.Minute)
		}
		b = b.Expiration(exp)
	}
	if !o.nbf.IsZero() {
		b = b.NotBefore(o.nbf)
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if !o.skipScope {
		if err := tok.Set("scope", o.scope); err != nil {
			t.Fatal(err)
		}
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(i.alg, i.priv))
	if err != nil {
		t.Fatalf("jwt.Sign: %v", err)
	}
	return string(signed)
}

func writeJWKSFile(t *testing.T, set jwk.Set) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "jwks.json")
	buf, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newFileValidator(t *testing.T, set jwk.Set, audience string) Validator {
	t.Helper()
	path := writeJWKSFile(t, set)
	v, err := New(context.Background(), Config{
		JWKS:     JWKSConfig{FilePath: path},
		Audience: audience,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

func TestValidator_RS256_HappyPath(t *testing.T) {
	iss := newRSAIssuer(t, "k1")
	v := newFileValidator(t, iss.publicSet, "amf.local")
	tok := iss.sign(t, tokenOpts{sub: "AMF-uuid-1", aud: "amf.local", scope: "nausf-auth"})

	c, err := v.Validate(context.Background(), tok, nil)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if c.Subject != "AMF-uuid-1" {
		t.Errorf("Subject = %q", c.Subject)
	}
	if c.Audience != "amf.local" {
		t.Errorf("Audience = %q", c.Audience)
	}
	if !HasScope(c.Scope, "nausf-auth") {
		t.Errorf("Scope = %q", c.Scope)
	}
}

func TestValidator_ES256_HappyPath(t *testing.T) {
	iss := newECIssuer(t, "k-ec1")
	v := newFileValidator(t, iss.publicSet, "amf.local")
	tok := iss.sign(t, tokenOpts{sub: "AMF-ec-1", aud: "amf.local", scope: "nudm-sdm"})

	if _, err := v.Validate(context.Background(), tok, nil); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidator_RejectsExpired(t *testing.T) {
	iss := newRSAIssuer(t, "k1")
	v := newFileValidator(t, iss.publicSet, "amf.local")
	tok := iss.sign(t, tokenOpts{
		sub:   "AMF-uuid-1",
		aud:   "amf.local",
		scope: "nausf-auth",
		exp:   time.Now().Add(-2 * time.Minute), // outside default 30s skew
	})

	_, err := v.Validate(context.Background(), tok, nil)
	mustReason(t, err, ReasonExpired)
}

func TestValidator_AcceptsWithinClockSkew(t *testing.T) {
	iss := newRSAIssuer(t, "k1")
	v := newFileValidator(t, iss.publicSet, "amf.local")
	// 10s past exp — within default 30s skew, must still pass.
	tok := iss.sign(t, tokenOpts{
		sub:   "AMF-uuid-1",
		aud:   "amf.local",
		scope: "nausf-auth",
		exp:   time.Now().Add(-10 * time.Second),
	})
	if _, err := v.Validate(context.Background(), tok, nil); err != nil {
		t.Fatalf("expected token within skew to validate, got %v", err)
	}
}

func TestValidator_RejectsWrongAudience(t *testing.T) {
	iss := newRSAIssuer(t, "k1")
	v := newFileValidator(t, iss.publicSet, "amf.local")
	tok := iss.sign(t, tokenOpts{sub: "x", aud: "smf.local", scope: "nausf-auth"})

	_, err := v.Validate(context.Background(), tok, nil)
	mustReason(t, err, ReasonWrongAudience)
}

// One audience per registered NF profile (the UDM's and the UDR's instance IDs): a token
// for either is accepted, any other is not.
func TestValidator_AudienceList(t *testing.T) {
	iss := newRSAIssuer(t, "k1")
	v := newFileValidator(t, iss.publicSet, " udm-id , udr-id,")
	for _, aud := range []string{"udm-id", "udr-id"} {
		tok := iss.sign(t, tokenOpts{sub: "AMF-1", aud: aud, scope: "nudm-sdm"})
		if _, err := v.Validate(context.Background(), tok, nil); err != nil {
			t.Fatalf("aud %q: %v", aud, err)
		}
	}
	tok := iss.sign(t, tokenOpts{sub: "AMF-1", aud: "udm-id,udr-id", scope: "nudm-sdm"})
	_, err := v.Validate(context.Background(), tok, nil)
	mustReason(t, err, ReasonWrongAudience)
	tok = iss.sign(t, tokenOpts{sub: "AMF-1", skipAud: true, scope: "nudm-sdm"})
	_, err = v.Validate(context.Background(), tok, nil)
	mustReason(t, err, ReasonWrongAudience)
}

func TestSplitAudience(t *testing.T) {
	if got := SplitAudience(" a,,b , "); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("SplitAudience: %q", got)
	}
	if got := SplitAudience(" , "); len(got) != 0 {
		t.Fatalf("SplitAudience of blanks: %q", got)
	}
}

func TestValidator_RejectsMissingClaim(t *testing.T) {
	iss := newRSAIssuer(t, "k1")
	v := newFileValidator(t, iss.publicSet, "amf.local")
	// scope omitted → required-claim violation
	tok := iss.sign(t, tokenOpts{sub: "x", aud: "amf.local", skipScope: true})

	_, err := v.Validate(context.Background(), tok, nil)
	mustReason(t, err, ReasonMissingClaim)
}

// sub is the consumer NF's identity and the rate limiter's key: a token without one, or
// with an empty one, is refused.
func TestValidator_RejectsMissingOrEmptySub(t *testing.T) {
	iss := newRSAIssuer(t, "k1")
	v := newFileValidator(t, iss.publicSet, "amf.local")
	for name, opts := range map[string]tokenOpts{
		"no sub":    {skipSub: true, aud: "amf.local", scope: "nudm-ueau"},
		"empty sub": {sub: "", aud: "amf.local", scope: "nudm-ueau"},
	} {
		_, err := v.Validate(context.Background(), iss.sign(t, opts), nil)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		mustReason(t, err, ReasonMissingClaim)
	}
}

func TestValidator_RejectsUnknownKid(t *testing.T) {
	good := newRSAIssuer(t, "k1")
	rogue := newRSAIssuer(t, "k-rogue") // never added to validator's set
	v := newFileValidator(t, good.publicSet, "amf.local")

	tok := rogue.sign(t, tokenOpts{sub: "x", aud: "amf.local", scope: "nausf-auth"})
	_, err := v.Validate(context.Background(), tok, nil)
	ve, ok := AsValidationError(err)
	if !ok {
		t.Fatalf("expected ValidationError, got %T %v", err, err)
	}
	// Either unknown_kid or invalid_signature is acceptable here — both
	// mean "this token cannot be trusted." Pinning the exact reason would
	// couple the test to jwx error wording.
	if ve.Reason != ReasonUnknownKid && ve.Reason != ReasonInvalidSig {
		t.Fatalf("expected unknown_kid or invalid_signature, got %q", ve.Reason)
	}
}

func TestValidator_RejectsMissingToken(t *testing.T) {
	iss := newRSAIssuer(t, "k1")
	v := newFileValidator(t, iss.publicSet, "amf.local")
	_, err := v.Validate(context.Background(), "   ", nil)
	mustReason(t, err, ReasonMissingToken)
}

func TestValidator_RejectsMalformed(t *testing.T) {
	iss := newRSAIssuer(t, "k1")
	v := newFileValidator(t, iss.publicSet, "amf.local")
	_, err := v.Validate(context.Background(), "not.a.jwt", nil)
	if _, ok := AsValidationError(err); !ok {
		t.Fatalf("expected ValidationError, got %T %v", err, err)
	}
}

func TestValidator_DropsHS256AtFilter(t *testing.T) {
	// Build a JWKS containing an HS256 key. filterByAlg must drop it; an
	// HS256 token signed against it must NOT validate even when the kid
	// matches, because the key never enters the validator's set.
	hsKey, err := jwk.FromRaw([]byte("super-secret-shared-key-32bytes!!"))
	if err != nil {
		t.Fatal(err)
	}
	_ = hsKey.Set(jwk.AlgorithmKey, jwa.HS256)
	_ = hsKey.Set(jwk.KeyIDKey, "k-hs")

	rsaIss := newRSAIssuer(t, "k-rsa")
	mixed := jwk.NewSet()
	if err := mixed.AddKey(hsKey); err != nil {
		t.Fatal(err)
	}
	pub, _ := rsaIss.priv.PublicKey()
	if err := mixed.AddKey(pub); err != nil {
		t.Fatal(err)
	}

	v := newFileValidator(t, mixed, "amf.local")

	// HS256 token signed with the shared secret — even though kid matches
	// "k-hs", filterByAlg dropped that key, so verification must fail.
	hsTok := jwt.New()
	_ = hsTok.Set(jwt.SubjectKey, "x")
	_ = hsTok.Set(jwt.AudienceKey, []string{"amf.local"})
	_ = hsTok.Set(jwt.ExpirationKey, time.Now().Add(5*time.Minute))
	_ = hsTok.Set("scope", "nausf-auth")
	signed, err := jwt.Sign(hsTok, jwt.WithKey(jwa.HS256, hsKey))
	if err != nil {
		t.Fatalf("jwt.Sign HS256: %v", err)
	}
	if _, err := v.Validate(context.Background(), string(signed), nil); err == nil {
		t.Fatalf("HS256 token unexpectedly accepted; alg allowlist breached")
	}

	// RS256 sibling on the same set still works — the filter dropped only
	// the HS256 key, not the entire set.
	rsTok := rsaIss.sign(t, tokenOpts{sub: "x", aud: "amf.local", scope: "nausf-auth"})
	if _, err := v.Validate(context.Background(), rsTok, nil); err != nil {
		t.Fatalf("RS256 sibling failed: %v", err)
	}
}

func TestValidator_PositiveCacheRespectsTokenExp(t *testing.T) {
	iss := newRSAIssuer(t, "k1")
	v, err := New(context.Background(), Config{
		JWKS:           JWKSConfig{FilePath: writeJWKSFile(t, iss.publicSet)},
		Audience:       "amf.local",
		ResultCacheTTL: 1 * time.Hour,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	// Token expires in 1s; cache TTL is 1 hour. After the token expires,
	// the cache must NOT keep returning success — the cache cap-to-exp
	// logic is the protection here.
	tok := iss.sign(t, tokenOpts{
		sub:   "x",
		aud:   "amf.local",
		scope: "nausf-auth",
		exp:   time.Now().Add(1 * time.Second),
	})
	if _, err := v.Validate(context.Background(), tok, nil); err != nil {
		t.Fatalf("first validate: %v", err)
	}
	// Wait past token expiry + clock skew default (30s) — keep this test
	// fast by lowering skew? No — that would test less. Use a short-lived
	// token and a tight cache TTL instead.
	internal := v.(*validator)
	internal.skew = 0 // pin to zero so we don't have to sleep 31s
	time.Sleep(1100 * time.Millisecond)
	_, err = v.Validate(context.Background(), tok, nil)
	if err == nil {
		t.Fatalf("expected expired-after-cache rejection, got success")
	}
}

func TestJWKSFile_RejectsEmptyAfterFilter(t *testing.T) {
	// JWKS containing only an HS256 key → filter empties the set →
	// loadJWKSFile must return an error so the operator notices at startup
	// instead of every token silently failing in production.
	hsKey, _ := jwk.FromRaw([]byte("super-secret-shared-key-32bytes!!"))
	_ = hsKey.Set(jwk.AlgorithmKey, jwa.HS256)
	_ = hsKey.Set(jwk.KeyIDKey, "k-hs")
	set := jwk.NewSet()
	_ = set.AddKey(hsKey)

	dir := t.TempDir()
	path := filepath.Join(dir, "jwks.json")
	buf, _ := json.Marshal(set)
	_ = os.WriteFile(path, buf, 0o600)

	if _, err := loadJWKSFile(path); err == nil {
		t.Fatalf("expected error for empty-after-filter JWKS, got nil")
	}
}

func TestNew_RejectsMissingAudience(t *testing.T) {
	iss := newRSAIssuer(t, "k1")
	_, err := New(context.Background(), Config{
		JWKS: JWKSConfig{FilePath: writeJWKSFile(t, iss.publicSet)},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatalf("expected error when Audience missing")
	}
}

func TestNew_RejectsMissingJWKS(t *testing.T) {
	_, err := New(context.Background(), Config{
		Audience: "amf.local",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatalf("expected error when JWKS source missing")
	}
}

// TestNRFCachedSource_PrimesAtStartup spins up a fake NRF JWKS endpoint and
// confirms the cache-backed source can validate tokens minted against keys
// served by that endpoint. This is the only test that exercises the network
// path — keep it fast with httptest.
func TestNRFCachedSource_PrimesAtStartup(t *testing.T) {
	iss := newRSAIssuer(t, "k1")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(iss.publicSet)
	}))
	defer srv.Close()

	v, err := New(context.Background(), Config{
		JWKS:     JWKSConfig{NRFURL: srv.URL, RefreshInterval: 1 * time.Minute},
		Audience: "amf.local",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tok := iss.sign(t, tokenOpts{sub: "x", aud: "amf.local", scope: "nausf-auth"})
	if _, err := v.Validate(context.Background(), tok, nil); err != nil {
		t.Fatalf("Validate via cached NRF source: %v", err)
	}
}

// mustReason asserts err is a *ValidationError with the expected reason.
// Inline t.Fatal saves seven near-identical helpers across tests.
func mustReason(t *testing.T, err error, want FailReason) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected ValidationError(%s), got nil", want)
	}
	ve, ok := AsValidationError(err)
	if !ok {
		t.Fatalf("expected ValidationError, got %T: %v", err, err)
	}
	if ve.Reason != want {
		t.Fatalf("expected reason %q, got %q (err: %v)", want, ve.Reason, err)
	}
}

// Readiness follows the keys: with OAuth on and no key from the NRF yet, every token is
// rejected, so the gateway must not be ready (A.8).
func TestReady_FollowsNRFKeys(t *testing.T) {
	iss := newRSAIssuer(t, "k1")
	var serve atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !serve.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(iss.publicSet)
	}))
	defer srv.Close()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	down, err := New(context.Background(), Config{JWKS: JWKSConfig{NRFURL: srv.URL}, Audience: "amf.local"}, quiet)
	if err != nil {
		t.Fatal(err)
	}
	if Ready(down) {
		t.Error("ready without a key")
	}

	serve.Store(true)
	up, err := New(context.Background(), Config{JWKS: JWKSConfig{NRFURL: srv.URL}, Audience: "amf.local"}, quiet)
	if err != nil {
		t.Fatal(err)
	}
	if !Ready(up) {
		t.Error("not ready with the NRF's key")
	}
	if !Ready(newFileValidator(t, iss.publicSet, "amf.local")) {
		t.Error("a JWKS file validator not ready")
	}
}

// An NRF that accepts the connection and never answers holds start-up for the fetch timeout,
// not indefinitely (0.2.x used http.DefaultClient, which has none).
func TestJWKS_FetchTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	saved := jwksFetchTimeout
	jwksFetchTimeout = 200 * time.Millisecond
	defer func() { jwksFetchTimeout = saved }()

	start := time.Now()
	v, err := New(context.Background(), Config{JWKS: JWKSConfig{NRFURL: srv.URL}, Audience: "amf.local"},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("start-up held %s by an NRF that does not answer", elapsed)
	}
	if Ready(v) {
		t.Error("ready without a key")
	}
}

// Short refresh intervals register: 0.2.x halved the interval into a refresh window, which
// httprc replaces with 15 m under 1 s and then refuses, so OAUTH_JWKS_REFRESH below 2 s
// stopped the gateway with an error about a window nobody set. Below 1 s is refused plainly.
func TestJWKS_ShortRefreshInterval(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer srv.Close()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, interval := range []time.Duration{time.Second, 1500 * time.Millisecond} {
		if _, err := New(context.Background(), Config{JWKS: JWKSConfig{NRFURL: srv.URL, RefreshInterval: interval}, Audience: "a"}, quiet); err != nil {
			t.Errorf("refresh %s: %v", interval, err)
		}
	}
	_, err := New(context.Background(), Config{JWKS: JWKSConfig{NRFURL: srv.URL, RefreshInterval: 500 * time.Millisecond}, Audience: "a"}, quiet)
	if err == nil || !strings.Contains(err.Error(), "OAUTH_JWKS_REFRESH") {
		t.Errorf("refresh 500ms: %v, want an error naming OAUTH_JWKS_REFRESH", err)
	}
}

// A gateway started while the NRF was down becomes ready soon after the NRF answers, not one
// refresh interval later: httprc schedules the fetch after a failed one at the full interval
// (5 m by default), so the source retries every NegativeTTL while it holds no key.
func TestJWKS_RecoversAfterFailedStart(t *testing.T) {
	iss := newRSAIssuer(t, "k1")
	var serve atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !serve.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(iss.publicSet)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	v, err := New(ctx, Config{
		JWKS:     JWKSConfig{NRFURL: srv.URL, RefreshInterval: time.Hour, NegativeTTL: 100 * time.Millisecond},
		Audience: "amf.local",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if Ready(v) {
		t.Fatal("ready without a key")
	}
	serve.Store(true)
	deadline := time.Now().Add(3 * time.Second)
	for !Ready(v) {
		if time.Now().After(deadline) {
			t.Fatal("not ready 3 s after the NRF answered")
		}
		time.Sleep(20 * time.Millisecond)
	}
	tok := iss.sign(t, tokenOpts{sub: "x", aud: "amf.local", scope: "nausf-auth"})
	if _, err := v.Validate(context.Background(), tok, nil); err != nil {
		t.Errorf("Validate after recovery: %v", err)
	}
}
