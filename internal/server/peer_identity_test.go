// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	tlsgen "github.com/3eAI-Labs/sbi-ha-gateway/internal/testutil/tlsgen"
)

func TestExtractNFInstanceID_PrefixMatch(t *testing.T) {
	u, _ := url.Parse("urn:5g:nf-instance-id:550e8400-e29b-41d4-a716-446655440000")
	cert := &x509.Certificate{URIs: []*url.URL{u}}
	got := extractNFInstanceID(cert)
	want := "550e8400-e29b-41d4-a716-446655440000"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestExtractNFInstanceID_FirstMatchWins(t *testing.T) {
	first, _ := url.Parse("urn:5g:nf-instance-id:first")
	second, _ := url.Parse("urn:5g:nf-instance-id:second")
	cert := &x509.Certificate{URIs: []*url.URL{first, second}}
	if got := extractNFInstanceID(cert); got != "first" {
		t.Errorf("got %q, want first", got)
	}
}

func TestExtractNFInstanceID_IgnoresNonNFURIs(t *testing.T) {
	other, _ := url.Parse("https://amf-1.5gc.local/")
	nf, _ := url.Parse("urn:5g:nf-instance-id:correct")
	cert := &x509.Certificate{URIs: []*url.URL{other, nf}}
	if got := extractNFInstanceID(cert); got != "correct" {
		t.Errorf("expected non-3GPP URIs to be skipped; got %q", got)
	}
}

func TestExtractNFInstanceID_EmptyWhenAbsent(t *testing.T) {
	other, _ := url.Parse("https://amf-1.5gc.local/")
	cert := &x509.Certificate{URIs: []*url.URL{other}}
	if got := extractNFInstanceID(cert); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestPeerIdentityMiddleware_NoTLS_Passthrough(t *testing.T) {
	called := false
	h := PeerIdentityMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		called = true
		if id := PeerIdentityFromContext(r.Context()); id != nil {
			t.Errorf("expected nil identity for non-TLS request; got %+v", id)
		}
	}))
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called {
		t.Fatal("downstream handler not invoked")
	}
}

func TestPeerIdentityMiddleware_NoPeerCert_Passthrough(t *testing.T) {
	called := false
	h := PeerIdentityMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		called = true
		if id := PeerIdentityFromContext(r.Context()); id != nil {
			t.Errorf("expected nil identity when no peer certs; got %+v", id)
		}
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{} // TLS but no peer certs
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called {
		t.Fatal("downstream handler not invoked")
	}
}

func TestPeerIdentityMiddleware_InjectsIdentity(t *testing.T) {
	ca := tlsgen.NewCA(t)
	uri, _ := url.Parse("urn:5g:nf-instance-id:amf-uuid-42")
	leaf := ca.Sign(t, tlsgen.LeafSpec{
		CommonName: "amf-1",
		URIs:       []*url.URL{uri},
		IsClient:   true,
	})

	var captured *PeerIdentity
	h := PeerIdentityMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		captured = PeerIdentityFromContext(r.Context())
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf.Cert}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if captured == nil {
		t.Fatal("identity not injected into context")
	}
	if captured.NFInstanceID != "amf-uuid-42" {
		t.Errorf("NFInstanceID = %q", captured.NFInstanceID)
	}
	tp := captured.CertThumbprint()
	if len(tp) != 32 {
		t.Errorf("thumbprint length = %d, want 32 (SHA-256)", len(tp))
	}
}

func TestPeerIdentity_CertThumbprint_NilSafe(t *testing.T) {
	var p *PeerIdentity
	if tp := p.CertThumbprint(); tp != nil {
		t.Errorf("nil receiver should return nil thumbprint; got %v", tp)
	}
	p2 := &PeerIdentity{}
	if tp := p2.CertThumbprint(); tp != nil {
		t.Errorf("nil cert should return nil thumbprint; got %v", tp)
	}
}
