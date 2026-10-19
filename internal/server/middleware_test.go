// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
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
	// Request with no chi.RouteContext attached → unmatchedRoute, never the path.
	req := httptest.NewRequest(http.MethodGet, "/raw/imsi-001010000000001", nil)
	assert.Equal(t, unmatchedRoute, getRoutePattern(req))
}

func TestGetRoutePattern_UnmatchedRoute(t *testing.T) {
	// chi RouteContext exists but no matching route → empty pattern → unmatchedRoute: the
	// path is the client's, and may carry a SUPI or a new metric label per request.
	r := chi.NewRouter()
	r.Get("/known", func(w http.ResponseWriter, _ *http.Request) {})

	var captured string
	r.NotFound(func(w http.ResponseWriter, req *http.Request) {
		captured = getRoutePattern(req)
		w.WriteHeader(http.StatusNotFound)
	})

	req := httptest.NewRequest(http.MethodGet, "/nudm-xyz/v1/imsi-001010000000001", nil)
	r.ServeHTTP(httptest.NewRecorder(), req)

	assert.Equal(t, unmatchedRoute, captured)
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

// A method the client makes up is OTHER in the metric labels, not a series of its own.
func TestMetricsMiddleware_MethodLabelBounded(t *testing.T) {
	r := chi.NewRouter()
	r.Use(MetricsMiddleware)
	r.Get("/x", func(http.ResponseWriter, *http.Request) {})
	for _, m := range []string{"FOO1", "FOO2", "GET"} {
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(m, "/x", nil))
	}
	for _, c := range []struct {
		method string
		want   bool
	}{{"FOO1", false}, {"FOO2", false}, {"OTHER", true}, {"GET", true}} {
		var found bool
		ch := make(chan prometheus.Metric, 64)
		metrics.RequestsTotal.Collect(ch)
		close(ch)
		for m := range ch {
			var d dto.Metric
			_ = m.Write(&d)
			for _, l := range d.GetLabel() {
				if l.GetName() == "method" && l.GetValue() == c.method {
					found = true
				}
			}
		}
		assert.Equal(t, c.want, found, "series with method %q", c.method)
	}
}
