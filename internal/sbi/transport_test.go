// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package sbi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/testutil/tlsgen"
)

// The client's own transport, not a replacement: callbacks go out over HTTP/2 only —
// unencrypted with prior knowledge to http:// URIs when no outbound TLS is configured, over
// TLS to https:// URIs, with the client certificate under mTLS — and never in cleartext once
// outbound TLS is configured.

type seen struct {
	proto      atomic.Int32
	peerCerts  atomic.Int32
	callbacked atomic.Bool
}

func (s *seen) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.proto.Store(int32(r.ProtoMajor))
		if r.TLS != nil {
			s.peerCerts.Store(int32(len(r.TLS.PeerCertificates)))
		}
		s.callbacked.Store(true)
		w.WriteHeader(http.StatusNoContent)
	})
}

func h2cServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	srv.Config.Protocols = &p
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// tlsServer serves h over TLS with a certificate signed by ca, HTTP/2 when http2, and asks
// for a client certificate signed by ca when clientAuth.
func tlsServer(t *testing.T, ca *tlsgen.CA, h http.Handler, http2, clientAuth bool) *httptest.Server {
	t.Helper()
	leaf := ca.Sign(t, tlsgen.LeafSpec{CommonName: "nf.test", IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	cert, err := tls.X509KeyPair(leaf.CertPEM, leaf.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	if clientAuth {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(ca.PEM)
		srv.TLS.ClientAuth = tls.RequireAndVerifyClientCert
		srv.TLS.ClientCAs = pool
	}
	srv.EnableHTTP2 = http2
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// mtlsServer requires a client certificate signed by ca.
func mtlsServer(t *testing.T, ca *tlsgen.CA, h http.Handler) *httptest.Server {
	return tlsServer(t, ca, h, true, true)
}

// caFile writes ca's certificate to a file in a test directory.
func caFile(t *testing.T, ca *tlsgen.CA) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, ca.PEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mtlsClient(t *testing.T, ca *tlsgen.CA) *AmfClient {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := ca.Sign(t, tlsgen.LeafSpec{CommonName: "sbi-gateway", IsClient: true}).WriteFiles(t, dir, "client")
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, ca.PEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultAmfClientConfig()
	cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSCAFile = certPath, keyPath, caPath
	c, err := NewAmfClientWithConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTransport_H2C(t *testing.T) {
	var s seen
	srv := h2cServer(t, s.handler())
	if err := NewAmfClient().SendCallback(context.Background(), srv.URL, map[string]int{"a": 1}); err != nil {
		t.Fatalf("SendCallback: %v", err)
	}
	if got := s.proto.Load(); got != 2 {
		t.Errorf("callback over HTTP/%d, want HTTP/2", got)
	}
}

func TestTransport_MTLS(t *testing.T) {
	ca := tlsgen.NewCA(t)
	var s seen
	srv := mtlsServer(t, ca, s.handler())
	if err := mtlsClient(t, ca).SendCallback(context.Background(), srv.URL, map[string]int{"a": 1}); err != nil {
		t.Fatalf("SendCallback: %v", err)
	}
	if got := s.proto.Load(); got != 2 {
		t.Errorf("callback over HTTP/%d, want HTTP/2", got)
	}
	if got := s.peerCerts.Load(); got != 1 {
		t.Errorf("server saw %d client certificates, want 1", got)
	}
}

// With mTLS configured, an http:// callback URI must fail, not be sent in cleartext.
func TestTransport_MTLSRefusesCleartext(t *testing.T) {
	var s seen
	srv := h2cServer(t, s.handler())
	if err := mtlsClient(t, tlsgen.NewCA(t)).SendCallback(context.Background(), srv.URL, map[string]int{"a": 1}); err == nil {
		t.Fatal("http:// callback sent with mTLS configured")
	}
	if s.callbacked.Load() {
		t.Error("the cleartext server received the notification")
	}
}

// Without any outbound TLS setting, an https:// URI gets HTTP/2 over TLS against the
// system roots (here the test CA stands in for them), never HTTP/1.1 (TS 29.500 clause 5.2.1).
func TestTransport_HTTPSWithoutTLSSettingsIsHTTP2(t *testing.T) {
	ca := tlsgen.NewCA(t)
	var s seen
	srv := tlsServer(t, ca, s.handler(), true, false)
	c := NewAmfClient()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.PEM)
	c.Client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	if err := c.SendCallback(context.Background(), srv.URL, map[string]int{"a": 1}); err != nil {
		t.Fatalf("SendCallback: %v", err)
	}
	if got := s.proto.Load(); got != 2 {
		t.Errorf("callback over HTTP/%d, want HTTP/2", got)
	}
}

// A CA alone is TLS without a client certificate: https:// URIs over HTTP/2, http:// ones
// refused.
func TestTransport_CAOnly(t *testing.T) {
	ca := tlsgen.NewCA(t)
	cfg := DefaultAmfClientConfig()
	cfg.TLSCAFile = caFile(t, ca)
	c, err := NewAmfClientWithConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var s seen
	srv := tlsServer(t, ca, s.handler(), true, false)
	if err := c.SendCallback(context.Background(), srv.URL, map[string]int{"a": 1}); err != nil {
		t.Fatalf("SendCallback: %v", err)
	}
	if got, certs := s.proto.Load(), s.peerCerts.Load(); got != 2 || certs != 0 {
		t.Errorf("HTTP/%d with %d client certificates, want HTTP/2 with none", got, certs)
	}

	var plain seen
	if err := c.SendCallback(context.Background(), h2cServer(t, plain.handler()).URL, map[string]int{"a": 1}); err == nil || plain.callbacked.Load() {
		t.Error("http:// callback sent with outbound TLS configured")
	}
}

// A peer that speaks only HTTP/1.1 over TLS is not called: the client never falls back.
func TestTransport_NoHTTP1OverTLS(t *testing.T) {
	ca := tlsgen.NewCA(t)
	cfg := DefaultAmfClientConfig()
	cfg.TLSCAFile = caFile(t, ca)
	c, err := NewAmfClientWithConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var s seen
	srv := tlsServer(t, ca, s.handler(), false, false)
	if err := c.SendCallback(context.Background(), srv.URL, map[string]int{"a": 1}); err == nil {
		t.Fatal("callback succeeded against an HTTP/1.1-only peer")
	}
	if s.callbacked.Load() {
		t.Error("the HTTP/1.1 peer received the notification")
	}
}
