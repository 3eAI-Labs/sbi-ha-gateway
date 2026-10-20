// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/config"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/testutil/tlsgen"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	natsserver "github.com/nats-io/nats-server/v2/server"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"sync/atomic"
)

func runServer(opts *natsserver.Options) *natsserver.Server {
	if opts == nil {
		opts = &natsserver.Options{
			Host: "127.0.0.1",
			Port: -1,
		}
	}
	s, err := natsserver.NewServer(opts)
	if err != nil {
		panic(err)
	}
	go s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		panic("not ready for connections")
	}
	return s
}

// insecureSBI sets the explicit opt-outs of a test gateway: cleartext SBI, no client
// certificates, no OAuth (none of them is a default).
func insecureSBI(t *testing.T) {
	t.Helper()
	t.Setenv("ALLOW_PLAINTEXT_SBI", "true")
	t.Setenv("MTLS_CLIENT_AUTH_MODE", "off")
	t.Setenv("OAUTH_DISABLED", "true")
	t.Setenv("ADMIN_TLS", "false")
	t.Setenv("ADMIN_AUTH_DISABLED", "true")
}

func TestRunWithContext(t *testing.T) {
	insecureSBI(t)
	s := runServer(nil)
	defer s.Shutdown()

	t.Setenv("NATS_URL", s.ClientURL())
	t.Setenv("SBI_PORT", "0")
	t.Setenv("ADMIN_PORT", "0")
	t.Setenv("SHUTDOWN_DRAIN_DELAY", "0s")

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunWithContext(ctx)
	}()

	// Wait for servers to start
	time.Sleep(100 * time.Millisecond)

	// Trigger shutdown via context cancellation
	cancel()

	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown timeout")
	}
}

func TestRunWithContext_NatsFailure(t *testing.T) {
	t.Setenv("NATS_URL", " %")

	ctx := context.Background()
	err := RunWithContext(ctx)
	assert.Error(t, err)
}

// Settings that would make the gateway run differently from what the operator asked
// stop it at start-up.
func TestRunWithContext_RejectsInvalidSettings(t *testing.T) {
	for name, env := range map[string][2]string{
		"unknown LOG_LEVEL":             {"LOG_LEVEL", "verbose"},
		"MAX_RETRIES 0":                 {"MAX_RETRIES", "0"},
		"NOTIFY_WORKERS 0":              {"NOTIFY_WORKERS", "0"},
		"negative RETRY_BASE_DELAY":     {"RETRY_BASE_DELAY", "-1s"},
		"negative SHUTDOWN_DRAIN_DELAY": {"SHUTDOWN_DRAIN_DELAY", "-1s"},
		"SHUTDOWN_TIMEOUT 0":            {"SHUTDOWN_TIMEOUT", "0s"},
		"ADMIN_TLS without TLS":         {"ADMIN_TLS", "true"},
		"no admin token":                {"ADMIN_AUTH_DISABLED", "false"},
		"token and auth disabled":       {"ADMIN_TOKEN_FILE", "/etc/hostname"},
		"OAUTH_DISABLED typo":           {"OAUTH_DISABLED", "fasle"},
	} {
		t.Run(name, func(t *testing.T) {
			insecureSBI(t)
			t.Setenv(env[0], env[1])
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := RunWithContext(ctx)
			if err == nil || !strings.Contains(err.Error(), env[0]) {
				t.Fatalf("got %v, want an error naming %s", err, env[0])
			}
		})
	}
}

// After the signal the SBI port goes on answering for SHUTDOWN_DRAIN_DELAY while the
// readiness probe fails, so that connections still routed to a terminating pod are served;
// only then does the gateway stop listening.
func TestRunWithContext_DrainsBeforeClosing(t *testing.T) {
	insecureSBI(t)
	s := runServer(nil)
	defer s.Shutdown()

	sbiPort, adminPort := freePort(t), freePort(t)
	t.Setenv("NATS_URL", s.ClientURL())
	t.Setenv("SBI_PORT", sbiPort)
	t.Setenv("ADMIN_PORT", adminPort)
	t.Setenv("SHUTDOWN_DRAIN_DELAY", "1s")
	ready := "http://127.0.0.1:" + adminPort + "/health/ready"
	sbi := "http://127.0.0.1:" + sbiPort + "/nudm-sdm/v2/imsi-001010000000001/am-data"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- RunWithContext(ctx) }()

	waitStatus(t, ready, http.StatusOK)
	cancel()
	signalled := time.Now()
	waitStatus(t, ready, http.StatusServiceUnavailable)

	// Any HTTP answer will do: no application is on NATS, so it is a 504.
	if _, err := getH2C(sbi); err != nil {
		t.Fatalf("SBI port refused a request during the drain: %v", err)
	}

	select {
	case err := <-errCh:
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, time.Since(signalled), time.Second, "stopped before the drain delay")
	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown timeout")
	}
	if _, err := getH2C(sbi); err == nil {
		t.Error("SBI port still answers after shutdown")
	}
}

// freePort returns a TCP port nothing listens on at the time of the call.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}

// get makes one request on a connection of its own.
func get(url string) (int, error) {
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := c.Get(url)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// getH2C makes one HTTP/2 request with prior knowledge, as on the SBI port.
func getH2C(url string) (int, error) {
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Protocols: &p, DisableKeepAlives: true}}
	resp, err := c.Get(url)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// waitStatus polls url until it answers want, for up to 5 seconds.
func waitStatus(t *testing.T, url string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, err := get(url)
		if err == nil && code == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: got %d (%v), want %d", url, code, err, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSBIServer_Timeouts(t *testing.T) {
	srv := sbiServer(":0", 2*time.Second, false)
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatalf("read/idle timeouts unset: %+v", srv)
	}
	if srv.WriteTimeout != 30*time.Second {
		t.Errorf("WriteTimeout = %s, want 30s", srv.WriteTimeout)
	}
	// The write timeout must outlast the wait for the application's reply.
	if got := sbiServer(":0", 45*time.Second, false).WriteTimeout; got != 55*time.Second {
		t.Errorf("WriteTimeout with a 45s NATS timeout = %s, want 55s", got)
	}
}

// HTTP/2 over TLS with TLS, h2c without; never cleartext HTTP/2 on a TLS port, never
// HTTP/1.1 (TS 29.500 clause 5.2.1).
func TestSBIServer_Protocols(t *testing.T) {
	if p := sbiServer(":0", 0, true).Protocols; !p.HTTP2() || p.UnencryptedHTTP2() || p.HTTP1() {
		t.Errorf("TLS: %s, want HTTP2 only", p)
	}
	if p := sbiServer(":0", 0, false).Protocols; p.HTTP2() || !p.UnencryptedHTTP2() || p.HTTP1() {
		t.Errorf("cleartext: %s, want UnencryptedHTTP2 only", p)
	}
}

// The SBI port speaks HTTP/2 only (TS 29.500 clause 5.2.1): HTTP/1.1 is refused on the
// cleartext port, and over TLS only h2 is negotiated.
func TestSBIServer_HTTP2Only(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	t.Run("cleartext", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := sbiServer("", time.Second, false)
		srv.Handler = ok
		go func() { _ = srv.Serve(ln) }()
		t.Cleanup(func() { _ = srv.Close() })
		url := "http://" + ln.Addr().String() + "/"
		if code, err := getH2C(url); err != nil || code != http.StatusNoContent {
			t.Errorf("h2c: %d, %v", code, err)
		}
		if code, err := get(url); err == nil {
			t.Errorf("HTTP/1.1 answered %d", code)
		}
	})

	t.Run("TLS", func(t *testing.T) {
		ca := tlsgen.NewCA(t)
		leaf := ca.Sign(t, tlsgen.LeafSpec{CommonName: "udm.test", IPs: []net.IP{net.ParseIP("127.0.0.1")}})
		cert, err := tls.X509KeyPair(leaf.CertPEM, leaf.KeyPEM)
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := sbiServer("", time.Second, true)
		srv.Handler = ok
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
		go func() { _ = srv.ServeTLS(ln, "", "") }()
		t.Cleanup(func() { _ = srv.Close() })

		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(ca.PEM)
		dial := func(protos ...string) (string, error) {
			conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: pool, NextProtos: protos})
			if err != nil {
				return "", err
			}
			defer func() { _ = conn.Close() }()
			return conn.ConnectionState().NegotiatedProtocol, nil
		}
		if p, err := dial("h2", "http/1.1"); err != nil || p != "h2" {
			t.Errorf("h2 and http/1.1 offered: %q, %v; want h2", p, err)
		}
		// crypto/tls completes a handshake in which the client offers http/1.1 alone, without
		// ALPN, for compatibility; the server must then not answer HTTP/1.1 on it.
		var h1 http.Protocols
		h1.SetHTTP1(true)
		c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			Protocols: &h1, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
		}}
		if resp, err := c.Get("https://" + ln.Addr().String() + "/"); err == nil {
			_ = resp.Body.Close()
			t.Errorf("HTTP/1.1 over TLS answered %d", resp.StatusCode)
		}
	})
}

// A port that cannot be bound stops the gateway at start-up, naming the port, rather than
// leaving a process that runs and reports ready without serving (0.2.x did).
func TestRunWithContext_BusyPort(t *testing.T) {
	s := runServer(nil)
	defer s.Shutdown()
	for name, env := range map[string]string{"SBI port": "SBI_PORT", "admin port": "ADMIN_PORT"} {
		t.Run(name, func(t *testing.T) {
			insecureSBI(t)
			busy, err := net.Listen("tcp", ":0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = busy.Close() }()
			t.Setenv("NATS_URL", s.ClientURL())
			t.Setenv("SBI_PORT", freePort(t))
			t.Setenv("ADMIN_PORT", freePort(t))
			t.Setenv(env, strconv.Itoa(busy.Addr().(*net.TCPAddr).Port))
			t.Setenv("SHUTDOWN_DRAIN_DELAY", "0s")

			done := make(chan error, 1)
			go func() { done <- RunWithContext(context.Background()) }()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), name) {
					t.Fatalf("got %v, want an error naming the %s", err, name)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("the gateway runs with its %s taken", name)
			}
		})
	}
}

// A certificate or key that cannot be loaded stops the gateway at start-up, before it
// listens; 0.2.x left the SBI server to fail in the background and reported ready.
func TestRunWithContext_UnreadableCertificate(t *testing.T) {
	s := runServer(nil)
	defer s.Shutdown()
	dir := t.TempDir()
	certPath, keyPath := tlsgen.NewCA(t).Sign(t, tlsgen.LeafSpec{CommonName: "udm.test"}).WriteFiles(t, dir, "sbi")
	if err := os.WriteFile(keyPath, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NATS_URL", s.ClientURL())
	t.Setenv("SBI_PORT", freePort(t))
	t.Setenv("ADMIN_PORT", freePort(t))
	t.Setenv("TLS_CERT_FILE", certPath)
	t.Setenv("TLS_KEY_FILE", keyPath)
	t.Setenv("MTLS_CLIENT_AUTH_MODE", "off")
	t.Setenv("OAUTH_DISABLED", "true")

	done := make(chan error, 1)
	go func() { done <- RunWithContext(context.Background()) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "TLS_CERT_FILE") {
			t.Fatalf("got %v, want the certificate load failure", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the gateway runs with an unusable certificate")
	}
}

// Secure by default: without settings the gateway refuses to start,
// naming what is missing, one protection at a time; with each opt-out explicit it starts.
func TestRunWithContext_SecureByDefault(t *testing.T) {
	s := runServer(nil)
	defer s.Shutdown()
	for _, c := range []struct {
		env  map[string]string
		want string // in the error; "" = starts
	}{
		{map[string]string{}, "ALLOW_PLAINTEXT_SBI"},
		{map[string]string{"ALLOW_PLAINTEXT_SBI": "true"}, "MTLS_CLIENT_AUTH_MODE"},
		{map[string]string{"ALLOW_PLAINTEXT_SBI": "true", "MTLS_CLIENT_AUTH_MODE": "off"}, "ADMIN_TLS"},
		{map[string]string{"ALLOW_PLAINTEXT_SBI": "true", "MTLS_CLIENT_AUTH_MODE": "off", "ADMIN_TLS": "false"}, "ADMIN_TOKEN_FILE"},
		{map[string]string{"ALLOW_PLAINTEXT_SBI": "true", "MTLS_CLIENT_AUTH_MODE": "off", "ADMIN_TLS": "false",
			"ADMIN_AUTH_DISABLED": "true"}, "OAUTH_AUDIENCE"},
		{map[string]string{"ALLOW_PLAINTEXT_SBI": "true", "MTLS_CLIENT_AUTH_MODE": "off", "ADMIN_TLS": "false",
			"ADMIN_AUTH_DISABLED": "true", "OAUTH_DISABLED": "true"}, ""},
	} {
		t.Run(c.want, func(t *testing.T) {
			for _, k := range []string{"ALLOW_PLAINTEXT_SBI", "MTLS_CLIENT_AUTH_MODE", "OAUTH_DISABLED", "ADMIN_TLS", "ADMIN_AUTH_DISABLED"} {
				t.Setenv(k, c.env[k])
			}
			t.Setenv("NATS_URL", s.ClientURL())
			t.Setenv("SBI_PORT", freePort(t))
			t.Setenv("ADMIN_PORT", freePort(t))
			t.Setenv("SHUTDOWN_DRAIN_DELAY", "0s")
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- RunWithContext(ctx) }()
			if c.want == "" {
				time.Sleep(200 * time.Millisecond)
				cancel()
			}
			select {
			case err := <-done:
				switch {
				case c.want == "" && err != nil:
					t.Fatalf("did not start: %v", err)
				case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
					t.Fatalf("got %v, want an error naming %s", err, c.want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no result")
			}
			cancel()
		})
	}
}

// Each protection switched off shows as a WARN line and a 0 gauge; one that is on, as 1.
func TestReportSecurity(t *testing.T) {
	var buf strings.Builder
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	reportSecurity(log, &config.Config{TLSCertFile: "c", TLSKeyFile: "k", MTLSClientAuthMode: "optional", OAuthDisabled: true})
	for name, want := range map[string]float64{"tls": 1, "client_certificate": 0, "oauth": 0, "outbound_destinations": 1} {
		var m dto.Metric
		if err := metrics.SecurityProtection.WithLabelValues(name).Write(&m); err != nil {
			t.Fatal(err)
		}
		if got := m.GetGauge().GetValue(); got != want {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	if n := strings.Count(buf.String(), `"msg":"SBI protection off"`); n != 2 || !strings.Contains(buf.String(), "MTLS_CLIENT_AUTH_MODE=optional") {
		t.Errorf("%d warnings: %s", n, buf.String())
	}
	// No destination listed, none allowed: said at start-up.
	if !strings.Contains(buf.String(), "No outbound destination allowed") {
		t.Errorf("no warning about outbound destinations: %s", buf.String())
	}
}

// The NRF's JWKS is fetched with the outbound TLS settings: their CA is the trust anchor and
// their certificate the gateway's identity, as towards every 5GC peer (A.8).
func TestJWKSHTTPClient_OutboundTLS(t *testing.T) {
	ca := tlsgen.NewCA(t)
	leaf := ca.Sign(t, tlsgen.LeafSpec{CommonName: "nrf.test", IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	serverCert, err := tls.X509KeyPair(leaf.CertPEM, leaf.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.PEM)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientCAs: pool,
		ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, ca.PEM, 0o600); err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := ca.Sign(t, tlsgen.LeafSpec{CommonName: "sbi-gateway", IsClient: true}).WriteFiles(t, dir, "gw")

	for name, c := range map[string]struct {
		cfg config.Config
		ok  bool
	}{
		"CA and certificate": {config.Config{MTLSOutboundCAFile: caFile, MTLSOutboundCertFile: certFile, MTLSOutboundKeyFile: keyFile}, true},
		"CA only":            {config.Config{MTLSOutboundCAFile: caFile}, false}, // the NRF asks for a certificate
		"no settings":        {config.Config{}, false},                           // system roots do not know the CA
	} {
		t.Run(name, func(t *testing.T) {
			client, err := jwksHTTPClient(&c.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if client.Timeout <= 0 {
				t.Error("no timeout")
			}
			resp, err := client.Get(srv.URL)
			if err == nil {
				_ = resp.Body.Close()
			}
			if (err == nil) != c.ok {
				t.Errorf("GET: %v, want success %v", err, c.ok)
			}
		})
	}
}

// With OAuth on, the gateway is not ready until the NRF has given it a verification key:
// every token would be rejected meanwhile (A.8). 0.2.x reported ready.
func TestRunWithContext_NotReadyWithoutJWKS(t *testing.T) {
	insecureSBI(t)
	s := runServer(nil)
	defer s.Shutdown()

	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.FromRaw(raw.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	_ = key.Set(jwk.AlgorithmKey, jwa.RS256)
	_ = key.Set(jwk.KeyIDKey, "k1")
	set := jwk.NewSet()
	_ = set.AddKey(key)
	var serve atomic.Bool
	nrf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !serve.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	defer nrf.Close()

	adminPort := freePort(t)
	t.Setenv("NATS_URL", s.ClientURL())
	t.Setenv("SBI_PORT", freePort(t))
	t.Setenv("ADMIN_PORT", adminPort)
	t.Setenv("SHUTDOWN_DRAIN_DELAY", "0s")
	t.Setenv("OAUTH_DISABLED", "false")
	t.Setenv("OAUTH_AUDIENCE", "udm-instance")
	t.Setenv("OAUTH_NRF_JWKS_URL", nrf.URL)
	t.Setenv("OAUTH_JWKS_REFRESH", "1s")
	ready := "http://127.0.0.1:" + adminPort + "/health/ready"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- RunWithContext(ctx) }()

	select {
	case err := <-errCh:
		t.Fatalf("the gateway did not start: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	waitStatus(t, ready, http.StatusServiceUnavailable)
	time.Sleep(500 * time.Millisecond)
	if code, _ := get(ready); code != http.StatusServiceUnavailable {
		t.Fatalf("ready %d with no verification key", code)
	}
	serve.Store(true)
	waitStatus(t, ready, http.StatusOK)

	cancel()
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("no shutdown")
	}
}

// The admin port over TLS with the SBI certificate and a token: the health endpoints answer
// without one, /metrics only with it, and cleartext is refused (A.11).
func TestRunWithContext_AdminTLSAndToken(t *testing.T) {
	insecureSBI(t)
	s := runServer(nil)
	defer s.Shutdown()
	dir := t.TempDir()
	certPath, keyPath := tlsgen.NewCA(t).Sign(t, tlsgen.LeafSpec{CommonName: "udm.test", IPs: []net.IP{net.ParseIP("127.0.0.1")}}).WriteFiles(t, dir, "sbi")
	tokenPath := filepath.Join(dir, "admin-token")
	if err := os.WriteFile(tokenPath, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	adminPort := freePort(t)
	t.Setenv("ALLOW_PLAINTEXT_SBI", "false")
	t.Setenv("TLS_CERT_FILE", certPath)
	t.Setenv("TLS_KEY_FILE", keyPath)
	t.Setenv("ADMIN_TLS", "true")
	t.Setenv("ADMIN_AUTH_DISABLED", "false")
	t.Setenv("ADMIN_TOKEN_FILE", tokenPath)
	t.Setenv("NATS_URL", s.ClientURL())
	t.Setenv("SBI_PORT", freePort(t))
	t.Setenv("ADMIN_PORT", adminPort)
	t.Setenv("SHUTDOWN_DRAIN_DELAY", "0s")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- RunWithContext(ctx) }()

	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- test: the probe does not verify either
	}}
	base := "https://127.0.0.1:" + adminPort
	status := func(path, token string) int {
		req, _ := http.NewRequest(http.MethodGet, base+path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	deadline := time.Now().Add(5 * time.Second)
	for status("/health/ready", "") != http.StatusOK {
		if time.Now().After(deadline) {
			t.Fatal("admin port not ready over TLS")
		}
		time.Sleep(50 * time.Millisecond)
	}
	assert.Equal(t, http.StatusOK, status("/health/live", ""))
	assert.Equal(t, http.StatusUnauthorized, status("/metrics", ""))
	assert.Equal(t, http.StatusOK, status("/metrics", "s3cret"))
	handshakes := func() float64 {
		var m dto.Metric
		_ = metrics.TLSHandshakeFailures.WithLabelValues("admin").Write(&m)
		return m.GetCounter().GetValue()
	}
	before := handshakes()
	if code, err := get("http://127.0.0.1:" + adminPort + "/health/live"); err == nil && code == http.StatusOK {
		t.Error("the admin port answered cleartext")
	}
	// The cleartext attempt is a handshake the admin port did not complete (C.8), and the
	// SBI certificate's expiry is exported.
	assert.Eventually(t, func() bool { return handshakes() > before }, 2*time.Second, 20*time.Millisecond)
	var expiry dto.Metric
	_ = metrics.TLSCertificateExpiry.WithLabelValues("sbi").Write(&expiry)
	assert.Greater(t, expiry.GetGauge().GetValue(), float64(time.Now().Unix()), "certificate expiry")

	cancel()
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("no shutdown")
	}
}

// An admin token file that cannot be read, or is empty, stops the gateway.
func TestRunWithContext_AdminTokenFileUnusable(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/nonexistent", empty} {
		insecureSBI(t)
		t.Setenv("ADMIN_AUTH_DISABLED", "false")
		t.Setenv("ADMIN_TOKEN_FILE", path)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := RunWithContext(ctx)
		cancel()
		if err == nil || !strings.Contains(err.Error(), "ADMIN_TOKEN_FILE") {
			t.Errorf("%s: %v, want an error naming ADMIN_TOKEN_FILE", path, err)
		}
	}
}
