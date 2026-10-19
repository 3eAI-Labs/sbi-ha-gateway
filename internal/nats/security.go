// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nats

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/nats-io/nats.go"
)

// Security is how the gateway authenticates to NATS and protects the connection. Secrets
// are files, never values: environment variables and pod specs show their values to
// anyone who can read them.
type Security struct {
	// Authentication: at most one of these.
	CredsFile    string // user JWT and NKey seed (decentralised authentication)
	NkeySeedFile string // a bare NKey seed
	User         string // with PasswordFile
	PasswordFile string
	TokenFile    string

	// TLS: on when any of these is set, or when the URL's scheme is tls://. TLS 1.3.
	CAFile   string // trust anchor of the NATS server's certificate; else the system roots
	CertFile string // client certificate, with KeyFile
	KeyFile  string
}

// options checks s against url (NATS_URL, possibly several comma-separated servers) and
// returns the connect options. Settings that contradict each other, or a secret file that
// cannot be read, are an error: the gateway must not connect otherwise than configured.
func (s Security) options(natsURL string) ([]nats.Option, error) {
	methods := 0
	for _, set := range []bool{s.CredsFile != "", s.NkeySeedFile != "", s.User != "" || s.PasswordFile != "", s.TokenFile != ""} {
		if set {
			methods++
		}
	}
	if methods > 1 {
		return nil, errors.New("NATS authentication: set one of NATS_CREDS_FILE, NATS_NKEY_SEED_FILE, NATS_USER with NATS_PASSWORD_FILE, NATS_TOKEN_FILE")
	}
	if (s.User == "") != (s.PasswordFile == "") {
		return nil, errors.New("NATS authentication: NATS_USER and NATS_PASSWORD_FILE go together")
	}
	if (s.CertFile == "") != (s.KeyFile == "") {
		return nil, errors.New("NATS TLS: NATS_TLS_CERT_FILE and NATS_TLS_KEY_FILE go together")
	}
	tlsScheme := false
	for _, server := range strings.Split(natsURL, ",") {
		u, err := url.Parse(strings.TrimSpace(server))
		if err != nil {
			continue // nats.Connect reports a malformed URL
		}
		if u.User != nil && methods > 0 {
			return nil, errors.New("NATS authentication: credentials both in NATS_URL and in NATS_* files; keep the files")
		}
		tlsScheme = tlsScheme || u.Scheme == "tls"
	}

	var opts []nats.Option
	switch {
	case s.CredsFile != "":
		if err := readable(s.CredsFile, "NATS_CREDS_FILE"); err != nil {
			return nil, err
		}
		opts = append(opts, nats.UserCredentials(s.CredsFile))
	case s.NkeySeedFile != "":
		opt, err := nats.NkeyOptionFromSeed(s.NkeySeedFile)
		if err != nil {
			return nil, fmt.Errorf("NATS_NKEY_SEED_FILE: %w", err)
		}
		opts = append(opts, opt)
	case s.User != "":
		password, err := secret(s.PasswordFile, "NATS_PASSWORD_FILE")
		if err != nil {
			return nil, err
		}
		opts = append(opts, nats.UserInfo(s.User, password))
	case s.TokenFile != "":
		token, err := secret(s.TokenFile, "NATS_TOKEN_FILE")
		if err != nil {
			return nil, err
		}
		opts = append(opts, nats.Token(token))
	}

	if s.CAFile != "" || s.CertFile != "" || tlsScheme {
		// First, so that RootCAs and ClientCert add to this configuration.
		opts = append(opts, nats.Secure(&tls.Config{MinVersion: tls.VersionTLS13}))
	}
	if s.CAFile != "" {
		opts = append(opts, nats.RootCAs(s.CAFile))
	}
	if s.CertFile != "" {
		opts = append(opts, nats.ClientCert(s.CertFile, s.KeyFile))
	}
	return opts, nil
}

// Describe says, without secrets, how the gateway authenticates and protects the
// connection, for the start-up log.
func (s Security) Describe(natsURL string) (auth, transport string) {
	switch {
	case s.CredsFile != "":
		auth = "user credentials"
	case s.NkeySeedFile != "":
		auth = "nkey"
	case s.User != "":
		auth = "user " + s.User
	case s.TokenFile != "":
		auth = "token"
	case strings.Contains(natsURL, "@"):
		auth = "in NATS_URL"
	default:
		auth = "none"
	}
	switch {
	case s.CertFile != "":
		transport = "TLS with a client certificate"
	case s.CAFile != "" || strings.Contains(natsURL, "tls://"):
		transport = "TLS"
	default:
		transport = "plaintext"
	}
	return auth, transport
}

func readable(path, name string) error {
	f, err := os.Open(path) // #nosec G304 -- path is the operator's NATS_* setting
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return f.Close()
}

// secret reads a password or token file, without its trailing newline.
func secret(path, name string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is the operator's NATS_* setting
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	value := strings.TrimRight(string(data), "\r\n")
	if value == "" {
		return "", fmt.Errorf("%s: empty", name)
	}
	return value, nil
}
