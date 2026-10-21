// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

// Package tlsgen produces synthetic CAs, server certs, and client certs in
// memory for use in tests. Real production cert provisioning is the
// operator's job (cert-manager / Vault / SPIRE / etc) — this package is
// strictly internal test scaffolding.
//
// The package is build-tag-free (no _test.go suffix) so multiple test
// packages can import it. Helpers take *testing.T so failures live in the
// caller's test, not here.
package tlsgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CA holds a freshly-generated certificate authority and its key. Use Sign()
// to mint leaf certificates trusted by this CA.
type CA struct {
	Cert    *x509.Certificate
	PrivKey *ecdsa.PrivateKey
	PEM     []byte // CA cert in PEM form, suitable for ClientCAs / RootCAs bundles
}

// NewCA generates a self-signed test CA. ECDSA P-256 keeps the cert small
// and matches the algorithm allowlist used by the OAuth validator.
func NewCA(t *testing.T) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sbi-ha-gateway test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CA{
		Cert:    cert,
		PrivKey: key,
		PEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// LeafSpec describes a leaf cert to mint.
type LeafSpec struct {
	CommonName string
	DNSNames   []string
	URIs       []*url.URL // 3GPP TS 33.310 URI SAN: urn:uuid:<UUID>
	IPs        []net.IP
	IsClient   bool // true → client auth EKU; false → server auth EKU
}

// Leaf is a minted certificate plus its key, ready for use in
// tls.LoadX509KeyPair (via PEM) or directly in tls.Certificate.
type Leaf struct {
	Cert    *x509.Certificate
	PrivKey *ecdsa.PrivateKey
	CertPEM []byte
	KeyPEM  []byte
	TLSCert []byte // raw DER, useful for SHA-256 thumbprinting in RFC 8705 tests
}

// Sign mints a leaf cert under the CA per spec.
func (ca *CA) Sign(t *testing.T, spec LeafSpec) *Leaf {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if spec.IsClient {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: spec.CommonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
		DNSNames:     spec.DNSNames,
		IPAddresses:  spec.IPs,
		URIs:         spec.URIs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.PrivKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &Leaf{
		Cert:    leaf,
		PrivKey: key,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		TLSCert: der,
	}
}

// WriteFiles writes a leaf's cert and key to dir as cert.pem / key.pem and
// returns their paths. Use this to drive code paths that read from disk
// (e.g., http.Server.ListenAndServeTLS).
func (l *Leaf) WriteFiles(t *testing.T, dir string, prefix string) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(dir, prefix+".crt")
	keyPath = filepath.Join(dir, prefix+".key")
	if err := os.WriteFile(certPath, l.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, l.KeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// WriteServerCert is a convenience: spin up a CA, mint a server cert with
// 127.0.0.1 + localhost SANs, write to dir, return file paths. Useful when
// the test only needs "some valid TLS cert" and doesn't care about the CA.
func WriteServerCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	ca := NewCA(t)
	leaf := ca.Sign(t, LeafSpec{
		CommonName: "test-server",
		DNSNames:   []string{"localhost"},
		IPs:        []net.IP{net.ParseIP("127.0.0.1")},
	})
	return leaf.WriteFiles(t, dir, "server")
}

// WriteCABundle writes a single freshly-generated CA cert to dir/ca.pem and
// returns the path. Used to populate the inbound MTLS_CLIENT_CA_FILE in
// tests that don't need to mint client certs from it.
func WriteCABundle(t *testing.T, dir string) string {
	t.Helper()
	ca := NewCA(t)
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, ca.PEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
