// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/authctx"
	"github.com/stretchr/testify/assert"
)

func TestNFRateLimit_Disabled(t *testing.T) {
	mw := NFRateLimitMiddleware(0, 100)
	called := 0
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 50; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("User-Agent", "AMF-test")
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	assert.Equal(t, 50, called, "rps=0 must be a passthrough")
}

func TestNFRateLimit_BurstThenReject(t *testing.T) {
	// 0.0001 RPS, burst 3 → only 3 requests succeed, the 4th is 429.
	mw := NFRateLimitMiddleware(0.0001, 3)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	statuses := make([]int, 5)
	for i := range statuses {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("User-Agent", "AMF-1")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		statuses[i] = rec.Code
	}

	assert.Equal(t, http.StatusOK, statuses[0])
	assert.Equal(t, http.StatusOK, statuses[1])
	assert.Equal(t, http.StatusOK, statuses[2])
	assert.Equal(t, http.StatusTooManyRequests, statuses[3])
	assert.Equal(t, http.StatusTooManyRequests, statuses[4])
}

func TestNFRateLimit_PerKeyIsolation(t *testing.T) {
	// Two NFs, separate buckets — exhausting one must not affect the other.
	mw := NFRateLimitMiddleware(0.0001, 1)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	hit := func(ua string) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("User-Agent", ua)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	assert.Equal(t, http.StatusOK, hit("AMF-1"))
	assert.Equal(t, http.StatusTooManyRequests, hit("AMF-1"))
	assert.Equal(t, http.StatusOK, hit("SMF-2"), "different NF must have its own bucket")
}

func TestNFKey_FallbackToRemoteIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.1.2.3:54321"
	req.Header.Del("User-Agent")
	assert.Equal(t, "10.1.2.3", nfKey(req))
}

func TestNFKey_UserAgentTrimsTrailing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "AMF-uuid-1 SBI/1.0 (linux)")
	assert.Equal(t, "AMF-uuid-1", nfKey(req))
}

func TestNFKey_PrefersOAuthSubject(t *testing.T) {
	// When OAuth middleware has injected a sub claim, it must win over UA
	// and IP. Otherwise a NF that obtained a token can still be tracked
	// per-instance even if it sits behind a shared User-Agent string.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "AMF-spoofed")
	req.RemoteAddr = "10.1.2.3:1234"
	req = req.WithContext(authctx.WithNFSubject(req.Context(), "AMF-real-uuid"))
	assert.Equal(t, "AMF-real-uuid", nfKey(req))
}

// Concurrent requests share the limiter's sweep counter: under -race, 0.2.x's unsynchronised
// increment is a data race.
func TestNFRateLimit_ConcurrentRequests(t *testing.T) {
	h := NFRateLimitMiddleware(1e6, 1e6)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("User-Agent", "AMF-1")
				h.ServeHTTP(httptest.NewRecorder(), req)
			}
		}()
	}
	wg.Wait()
}

// A 429 is ProblemDetails with TS 29.500's cause for it, and Retry-After.
func TestNFRateLimit_ProblemDetails(t *testing.T) {
	h := NFRateLimitMiddleware(0.0001, 1)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	var rec *httptest.ResponseRecorder
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("User-Agent", "AMF-1")
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
	}
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "1", rec.Header().Get("Retry-After"))
	assert.JSONEq(t, `{"title":"Too Many Requests","status":429,"cause":"NF_CONGESTION_RISK","detail":"Request rate above this client's limit"}`, rec.Body.String())
}
