// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
	"golang.org/x/time/rate"
)

// nfRateLimiter holds per-NF token buckets and trims stale entries.
//
// The key is the producer NF instance id, extracted from the request's
// User-Agent header (3GPP TS 29.500 §5.2.2.2 mandates the format
// "<nfType>-<nfInstanceId>"). When the header is missing or unparseable
// we fall back to the remote IP — IP-only is *not* the long-term plan in
// shared internal mesh, where many NFs may egress from the same pod.
type nfRateLimiter struct {
	rps   rate.Limit
	burst int
	ttl   time.Duration

	mu      sync.Mutex
	buckets map[string]*nfBucket
}

type nfBucket struct {
	limiter *rate.Limiter
	lastHit time.Time
}

func newNFRateLimiter(rps float64, burst int) *nfRateLimiter {
	return &nfRateLimiter{
		rps:     rate.Limit(rps),
		burst:   burst,
		ttl:     10 * time.Minute,
		buckets: make(map[string]*nfBucket),
	}
}

func (l *nfRateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		b = &nfBucket{limiter: rate.NewLimiter(l.rps, l.burst)}
		l.buckets[key] = b
	}
	b.lastHit = time.Now()
	return b.limiter.Allow()
}

// gc trims buckets idle longer than ttl. Called by the middleware on every
// request via a 1/N sampling — avoids spawning a dedicated goroutine that
// would have to be wired into shutdown.
func (l *nfRateLimiter) gc() {
	cutoff := time.Now().Add(-l.ttl)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if b.lastHit.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
}

// NFRateLimitMiddleware returns a chi middleware enforcing per-NF rate limits.
// When rps <= 0 the middleware is a passthrough (feature flag off).
func NFRateLimitMiddleware(rps float64, burst int) func(http.Handler) http.Handler {
	if rps <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	limiter := newNFRateLimiter(rps, burst)
	var counter uint64

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := nfKey(r)

			if !limiter.allow(key) {
				metrics.RecordError("rate_limit", "rejected")
				w.Header().Set("Retry-After", "1")
				http.Error(w, `{"status":429,"cause":"REQUEST_REJECTED"}`, http.StatusTooManyRequests)
				return
			}

			// Sweep stale buckets every ~1024 requests; cheap and predictable.
			counter++
			if counter%1024 == 0 {
				go limiter.gc()
			}

			next.ServeHTTP(w, r)
		})
	}
}

// nfKey extracts a stable per-NF identifier from the request.
// Order, most-trusted to least:
//  1. OAuth2 `sub` claim injected by OAuthMiddleware. This is the only key
//     source that survives an internal mesh where many NFs share a source IP
//     and User-Agent strings are spoofable — TS 33.501 §13.4.1 makes it the
//     authoritative identity once OAuth is enabled.
//  2. User-Agent prefix per TS 29.500 §5.2.2.2 ("AMF-<uuid>" → "AMF-<uuid>").
//  3. Remote IP (host portion only) as a last resort.
func nfKey(r *http.Request) string {
	if sub := NFSubjectFromContext(r.Context()); sub != "" {
		return sub
	}
	if ua := strings.TrimSpace(r.Header.Get("User-Agent")); ua != "" {
		// Strip any trailing tokens (e.g. "AMF-<id> SBI/1.0") — first whitespace token wins.
		if idx := strings.IndexAny(ua, " \t"); idx > 0 {
			return ua[:idx]
		}
		return ua
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
