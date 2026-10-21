// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"net/http"
	"strings"
)

// 3GPP TS 33.310 §6.1.3c.3 puts the NF instance identity of an NF certificate in a URI-ID
// subjectAltName: the NF instance ID (TS 29.571 §5.3.2, a UUID) as a URN, "urn:uuid:<UUID>"
// (NOTE 1). The prefix is matched exactly but for case — the URN namespace and the UUID's
// hex digits are case-insensitive (RFC 8141, RFC 4122) — with no fallback to the CN, because
// CN-based identity has been deprecated since RFC 6125 (2011) and is the usual source of
// bypass-via-CN-spoofing CVEs in mTLS implementations.
const nfInstanceIDURIPrefix = "urn:uuid:"

// PeerIdentity is the trusted identity extracted from a verified client cert.
// "Trusted" here means the cert chain was verified against ClientCAs by the
// TLS stack before this struct was populated — we do not re-verify.
type PeerIdentity struct {
	NFInstanceID string            // lower case; empty when no URI SAN matched the 3GPP prefix
	Cert         *x509.Certificate // the leaf cert, kept so RFC 8705 binding can hash it
}

// CertThumbprint returns the SHA-256 of the DER-encoded leaf cert per
// RFC 8705 §3.1. Returns nil when no cert is available.
func (p *PeerIdentity) CertThumbprint() []byte {
	if p == nil || p.Cert == nil {
		return nil
	}
	sum := sha256.Sum256(p.Cert.Raw)
	return sum[:]
}

type peerIdentityCtxKey struct{}

// PeerIdentityFromContext returns the verified peer identity, or nil when
// the request did not arrive over mTLS or no client cert was presented.
func PeerIdentityFromContext(ctx context.Context) *PeerIdentity {
	if v, ok := ctx.Value(peerIdentityCtxKey{}).(*PeerIdentity); ok {
		return v
	}
	return nil
}

// PeerIdentityMiddleware extracts the peer NF identity from the verified TLS
// peer cert and injects it into the request context. Runs unconditionally —
// when the connection is plaintext (h2c) or no peer cert was presented, the
// middleware is a passthrough and downstream code sees nil from
// PeerIdentityFromContext.
//
// This middleware MUST come before OAuthMiddleware in the chain so the
// validator can read the peer cert for RFC 8705 binding checks.
func PeerIdentityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		leaf := r.TLS.PeerCertificates[0] // 0 is always the leaf in tls.ConnectionState
		id := &PeerIdentity{
			NFInstanceID: extractNFInstanceID(leaf),
			Cert:         leaf,
		}
		ctx := context.WithValue(r.Context(), peerIdentityCtxKey{}, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractNFInstanceID returns the NF instance ID from the cert's URI SANs, in lower case,
// or "" if none match the 3GPP prefix. The first matching URI wins — presenting multiple
// distinct NF identities in one cert would itself be a configuration bug.
func extractNFInstanceID(cert *x509.Certificate) string {
	for _, u := range cert.URIs {
		if u == nil {
			continue
		}
		s := u.String()
		if len(s) > len(nfInstanceIDURIPrefix) && strings.EqualFold(s[:len(nfInstanceIDURIPrefix)], nfInstanceIDURIPrefix) {
			return strings.ToLower(s[len(nfInstanceIDURIPrefix):])
		}
	}
	return ""
}
