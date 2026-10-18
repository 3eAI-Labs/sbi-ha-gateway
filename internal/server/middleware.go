// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"net/http"
	"strconv"
	"time"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func RegisterMiddleware(r *chi.Mux) {
	r.Use(middleware.RequestID)
	// No RealIP: it believed X-Forwarded-For, X-Real-IP and True-Client-IP from
	// anyone. The client address is the TCP peer's.
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(MetricsMiddleware)
}

// MetricsMiddleware collects Prometheus metrics for each request
func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		metrics.IncActiveRequests()
		defer metrics.DecActiveRequests()

		// Wrap response writer to capture status code
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		next.ServeHTTP(ww, r)

		// Record metrics after request completes
		duration := time.Since(start).Seconds()
		status := strconv.Itoa(ww.Status())
		path := getRoutePattern(r)

		metrics.RecordRequest(r.Method, path, status, duration)
	})
}

// getRoutePattern extracts the chi route pattern for consistent metric labels.
// This prevents high cardinality from dynamic path segments like SUPI values.
// Example: /nudm-ueau/v1/imsi-123456789/auth-events -> /nudm-ueau/v1/{supiOrSuci}/auth-events
func getRoutePattern(r *http.Request) string {
	rctx := chi.RouteContext(r.Context())
	if rctx == nil {
		return r.URL.Path
	}

	// RoutePattern returns the template, e.g., /nudm-ueau/v1/{supiOrSuci}/auth-events
	pattern := rctx.RoutePattern()
	if pattern == "" {
		return r.URL.Path
	}

	return pattern
}
