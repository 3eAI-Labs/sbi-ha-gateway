// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nats

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/testutil/tlsgen"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"
)

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func startServer(t *testing.T, opts *natsserver.Options) *natsserver.Server {
	t.Helper()
	opts.Host, opts.Port = "127.0.0.1", -1
	s, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	go s.Start()
	if !s.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server not ready")
	}
	t.Cleanup(s.Shutdown)
	return s
}

// connects reports whether a client with sec gets connected to url within a second.
func connects(t *testing.T, url string, sec Security) bool {
	t.Helper()
	c, err := NewClientWithSecurity(url, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Second, sec)
	if err != nil {
		t.Fatalf("NewClientWithSecurity: %v", err)
	}
	defer c.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if c.IsConnected() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// Each authentication method against a server that requires it: the right secret
// connects, a wrong or missing one does not.
func TestSecurity_Authentication(t *testing.T) {
	t.Run("user and password", func(t *testing.T) {
		s := startServer(t, &natsserver.Options{Username: "gateway", Password: "s3cret"})
		if !connects(t, s.ClientURL(), Security{User: "gateway", PasswordFile: writeFile(t, "pw", "s3cret\n")}) {
			t.Error("not connected with the password")
		}
		if connects(t, s.ClientURL(), Security{User: "gateway", PasswordFile: writeFile(t, "pw", "wrong")}) {
			t.Error("connected with a wrong password")
		}
		if connects(t, s.ClientURL(), Security{}) {
			t.Error("connected without credentials")
		}
	})
	t.Run("token", func(t *testing.T) {
		s := startServer(t, &natsserver.Options{Authorization: "t0ken"})
		if !connects(t, s.ClientURL(), Security{TokenFile: writeFile(t, "token", "t0ken")}) {
			t.Error("not connected with the token")
		}
		if connects(t, s.ClientURL(), Security{TokenFile: writeFile(t, "token", "other")}) {
			t.Error("connected with a wrong token")
		}
	})
	t.Run("nkey", func(t *testing.T) {
		user, err := nkeys.CreateUser()
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := user.PublicKey()
		seed, _ := user.Seed()
		s := startServer(t, &natsserver.Options{Nkeys: []*natsserver.NkeyUser{{Nkey: pub}}})
		if !connects(t, s.ClientURL(), Security{NkeySeedFile: writeFile(t, "seed", string(seed))}) {
			t.Error("not connected with the nkey")
		}
		other, _ := nkeys.CreateUser()
		otherSeed, _ := other.Seed()
		if connects(t, s.ClientURL(), Security{NkeySeedFile: writeFile(t, "seed", string(otherSeed))}) {
			t.Error("connected with another nkey")
		}
	})
}

// TLS against a server that requires it, and client certificates against one that verifies
// them.
func TestSecurity_TLS(t *testing.T) {
	ca := tlsgen.NewCA(t)
	leaf := ca.Sign(t, tlsgen.LeafSpec{CommonName: "nats.test", IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	cert, err := tls.X509KeyPair(leaf.CertPEM, leaf.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	caFile := writeFile(t, "ca.pem", string(ca.PEM))
	clientCert, clientKey := ca.Sign(t, tlsgen.LeafSpec{CommonName: "sbi-gateway", IsClient: true}).WriteFiles(t, t.TempDir(), "client")

	t.Run("server TLS", func(t *testing.T) {
		s := startServer(t, &natsserver.Options{TLS: true, TLSTimeout: 2,
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}})
		if !connects(t, s.ClientURL(), Security{CAFile: caFile}) {
			t.Error("not connected over TLS with the CA")
		}
		if connects(t, s.ClientURL(), Security{}) {
			t.Error("connected to a TLS server without TLS settings")
		}
	})
	t.Run("client certificate", func(t *testing.T) {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(ca.PEM)
		s := startServer(t, &natsserver.Options{TLS: true, TLSVerify: true, TLSTimeout: 2,
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: pool,
				ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}})
		if !connects(t, s.ClientURL(), Security{CAFile: caFile, CertFile: clientCert, KeyFile: clientKey}) {
			t.Error("not connected with the client certificate")
		}
		if connects(t, s.ClientURL(), Security{CAFile: caFile}) {
			t.Error("connected without a client certificate")
		}
	})
}

// Settings that contradict each other, or secrets that cannot be read, stop the gateway
// before it connects anywhere.
func TestSecurity_InvalidSettings(t *testing.T) {
	pw := writeFile(t, "pw", "x")
	empty := writeFile(t, "empty", "\n")
	for name, c := range map[string]struct {
		url string
		sec Security
	}{
		"two methods":                {"nats://h:4222", Security{TokenFile: pw, User: "u", PasswordFile: pw}},
		"user without password":      {"nats://h:4222", Security{User: "u"}},
		"password without user":      {"nats://h:4222", Security{PasswordFile: pw}},
		"certificate without key":    {"nats://h:4222", Security{CertFile: pw}},
		"credentials in URL too":     {"nats://u:p@h:4222", Security{TokenFile: pw}},
		"unreadable password":        {"nats://h:4222", Security{User: "u", PasswordFile: "/nonexistent"}},
		"empty token":                {"nats://h:4222", Security{TokenFile: empty}},
		"unreadable creds":           {"nats://h:4222", Security{CredsFile: "/nonexistent"}},
		"seed that is not a seed":    {"nats://h:4222", Security{NkeySeedFile: pw}},
		"CA file that is not a cert": {"nats://h:4222", Security{CAFile: pw}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewClientWithSecurity(c.url, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Second, c.sec); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// The start-up log names the mode, never the secret.
func TestSecurity_Describe(t *testing.T) {
	for _, c := range []struct {
		url             string
		sec             Security
		auth, transport string
	}{
		{"nats://h:4222", Security{}, "none", "plaintext"},
		{"nats://u:secret@h:4222", Security{}, "in NATS_URL", "plaintext"},
		{"tls://h:4222", Security{User: "gw", PasswordFile: "/p"}, "user gw", "TLS"},
		{"nats://h:4222", Security{TokenFile: "/t", CAFile: "/ca", CertFile: "/c", KeyFile: "/k"}, "token", "TLS with a client certificate"},
	} {
		auth, transport := c.sec.Describe(c.url)
		if auth != c.auth || transport != c.transport || strings.Contains(auth+transport, "secret") {
			t.Errorf("%s %+v: %q, %q; want %q, %q", c.url, c.sec, auth, transport, c.auth, c.transport)
		}
	}
}
