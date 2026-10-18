// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	tlsutil "github.com/3eAI-Labs/sbi-ha-gateway/internal/testutil/tlsgen"
)

func TestBuildTLSConfig_Disabled(t *testing.T) {
	cfg, err := BuildTLSConfig(TLSOptions{})
	if err != nil || cfg != nil {
		t.Fatalf("expected (nil, nil) for disabled TLS, got (%v, %v)", cfg, err)
	}
}

func TestBuildTLSConfig_DisabledTLSWithMTLSCA_Fails(t *testing.T) {
	// MTLS without TLS underneath is non-sensical; we fail loudly so an
	// operator who set the CA file but forgot the cert/key sees the error.
	_, err := BuildTLSConfig(TLSOptions{
		ClientCAFile:   "/etc/sbi/ca.pem",
		ClientAuthMode: ClientAuthRequire,
	})
	if err == nil {
		t.Fatal("expected error when MTLS configured without TLS cert/key")
	}
}

// Each of these would serve cleartext h2c to an operator who asked for TLS.
func TestBuildTLSConfig_PartialTLS_Fails(t *testing.T) {
	for name, o := range map[string]TLSOptions{
		"certificate without key":  {CertFile: "/etc/sbi/tls.crt"},
		"key without certificate":  {KeyFile: "/etc/sbi/tls.key"},
		"require without TLS":      {ClientAuthMode: ClientAuthRequire},
		"optional without TLS":     {ClientAuthMode: ClientAuthOptional},
		"unknown mode without TLS": {ClientAuthMode: "requre"},
	} {
		if cfg, err := BuildTLSConfig(o); err == nil {
			t.Errorf("%s: got (%v, nil), want an error", name, cfg)
		}
	}
}

func TestBuildTLSConfig_RequireWithoutCA_Fails(t *testing.T) {
	dir := t.TempDir()
	cert, key := tlsutil.WriteServerCert(t, dir)
	_, err := BuildTLSConfig(TLSOptions{
		CertFile:       cert,
		KeyFile:        key,
		ClientAuthMode: ClientAuthRequire,
	})
	if err == nil {
		t.Fatal("expected error: require mode without CA file")
	}
}

func TestBuildTLSConfig_RequireMode(t *testing.T) {
	dir := t.TempDir()
	cert, key := tlsutil.WriteServerCert(t, dir)
	caFile := tlsutil.WriteCABundle(t, dir)

	cfg, err := BuildTLSConfig(TLSOptions{
		CertFile:       cert,
		KeyFile:        key,
		ClientCAFile:   caFile,
		ClientAuthMode: ClientAuthRequire,
	})
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d, want TLS 1.3 (%d)", cfg.MinVersion, tls.VersionTLS13)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Fatal("ClientCAs not populated")
	}
}

func TestBuildTLSConfig_OptionalMode(t *testing.T) {
	dir := t.TempDir()
	cert, key := tlsutil.WriteServerCert(t, dir)
	caFile := tlsutil.WriteCABundle(t, dir)

	cfg, err := BuildTLSConfig(TLSOptions{
		CertFile:       cert,
		KeyFile:        key,
		ClientCAFile:   caFile,
		ClientAuthMode: ClientAuthOptional,
	})
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Errorf("ClientAuth = %v, want VerifyClientCertIfGiven", cfg.ClientAuth)
	}
}

func TestBuildTLSConfig_OffMode(t *testing.T) {
	dir := t.TempDir()
	cert, key := tlsutil.WriteServerCert(t, dir)
	cfg, err := BuildTLSConfig(TLSOptions{
		CertFile: cert, KeyFile: key,
		ClientAuthMode: ClientAuthOff,
	})
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth = %v, want NoClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs != nil {
		t.Error("ClientCAs must be nil when auth is off")
	}
}

func TestBuildTLSConfig_BadAuthMode(t *testing.T) {
	dir := t.TempDir()
	cert, key := tlsutil.WriteServerCert(t, dir)
	_, err := BuildTLSConfig(TLSOptions{
		CertFile: cert, KeyFile: key,
		ClientAuthMode: "weakauth",
	})
	if err == nil {
		t.Fatal("expected error for unknown auth mode")
	}
}

func TestLoadCAPool_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(path, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCAPool(path); err == nil {
		t.Fatal("expected error for non-PEM file")
	}
}

func TestLoadCAPool_Valid(t *testing.T) {
	dir := t.TempDir()
	caFile := tlsutil.WriteCABundle(t, dir)
	pool, err := loadCAPool(caFile)
	if err != nil {
		t.Fatalf("loadCAPool: %v", err)
	}
	if pool == nil {
		t.Fatal("pool nil")
	}
	// Sanity check: there's at least one subject in the pool.
	subjects := pool.Subjects() //nolint:staticcheck // pool.Subjects deprecated only for system roots
	if len(subjects) == 0 {
		t.Fatal("pool has no subjects")
	}
	_ = (*x509.CertPool)(pool) // type sanity
}
