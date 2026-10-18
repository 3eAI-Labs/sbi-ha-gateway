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

// The client's own transport, not a replacement: callbacks go out over HTTP/2 —
// unencrypted with prior knowledge without mTLS, over TLS with the client certificate
// with mTLS — and never in cleartext once mTLS is configured.

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

// mtlsServer requires a client certificate signed by ca.
func mtlsServer(t *testing.T, ca *tlsgen.CA, h http.Handler) *httptest.Server {
	t.Helper()
	leaf := ca.Sign(t, tlsgen.LeafSpec{CommonName: "nf.test", IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	cert, err := tls.X509KeyPair(leaf.CertPEM, leaf.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.PEM)
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
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

// Without mTLS the client speaks h2c only; an https:// URI fails, as it did before.
func TestTransport_NoMTLSRefusesTLS(t *testing.T) {
	var s seen
	srv := mtlsServer(t, tlsgen.NewCA(t), s.handler())
	if err := NewAmfClient().SendCallback(context.Background(), srv.URL, map[string]int{"a": 1}); err == nil {
		t.Fatal("https:// callback succeeded without mTLS configuration")
	}
}
