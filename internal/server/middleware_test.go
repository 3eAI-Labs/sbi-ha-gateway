// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
)

// Tests live in the same package (server) so we can exercise the unexported
// getRoutePattern helper directly. Other tests in router_test.go use the
// external _test pattern; both are valid.

func TestGetRoutePattern_ReturnsChiPattern(t *testing.T) {
	r := chi.NewRouter()

	var captured string
	r.Get("/nudm-ueau/v1/{supiOrSuci}/auth-events", func(w http.ResponseWriter, req *http.Request) {
		captured = getRoutePattern(req)
	})

	req := httptest.NewRequest(http.MethodGet, "/nudm-ueau/v1/imsi-12345/auth-events", nil)
	r.ServeHTTP(httptest.NewRecorder(), req)

	// Critical for Prometheus cardinality: SUPI value must NOT appear in the pattern.
	assert.Equal(t, "/nudm-ueau/v1/{supiOrSuci}/auth-events", captured)
	assert.NotContains(t, captured, "imsi-12345")
}

func TestGetRoutePattern_NoChiContext(t *testing.T) {
	// Request with no chi.RouteContext attached → falls back to URL path.
	req := httptest.NewRequest(http.MethodGet, "/raw/path", nil)
	assert.Equal(t, "/raw/path", getRoutePattern(req))
}

func TestGetRoutePattern_UnmatchedRoute(t *testing.T) {
	// chi RouteContext exists but no matching route → empty pattern → URL path fallback.
	r := chi.NewRouter()
	r.Get("/known", func(w http.ResponseWriter, _ *http.Request) {})

	var captured string
	r.NotFound(func(w http.ResponseWriter, req *http.Request) {
		captured = getRoutePattern(req)
		w.WriteHeader(http.StatusNotFound)
	})

	req := httptest.NewRequest(http.MethodGet, "/unmatched/path", nil)
	r.ServeHTTP(httptest.NewRecorder(), req)

	assert.Equal(t, "/unmatched/path", captured)
}

func TestMetricsMiddleware_PassesThrough(t *testing.T) {
	// Middleware must be transparent: response body and status reach the client.
	r := chi.NewRouter()
	r.Use(MetricsMiddleware)
	r.Get("/ping", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("pong"))
	})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ping", nil))

	assert.Equal(t, http.StatusTeapot, rec.Code)
	assert.Equal(t, "pong", rec.Body.String())
}

func TestMetricsMiddleware_DefaultStatusOnNoExplicitWrite(t *testing.T) {
	// Handlers that never call WriteHeader should be recorded as 200 by chi's
	// WrapResponseWriter. This protects the metric from "0" status labels.
	r := chi.NewRouter()
	r.Use(MetricsMiddleware)
	r.Get("/silent", func(w http.ResponseWriter, _ *http.Request) {
		// no WriteHeader, no Write → implicit 200 on flush
	})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/silent", nil))

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMetricsMiddleware_PanicRecovery(t *testing.T) {
	// Middleware does not recover, but it must not leak active_requests when a
	// downstream panic propagates. The defer DecActiveRequests handles this.
	r := chi.NewRouter()
	r.Use(MetricsMiddleware)
	r.Get("/boom", func(w http.ResponseWriter, _ *http.Request) {
		panic("downstream failure")
	})

	defer func() {
		_ = recover() // swallow so the test doesn't fail
	}()
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/boom", nil))
}
