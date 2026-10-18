// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func RegisterMiddleware(r *chi.Mux, log *slog.Logger) {
	r.Use(middleware.RequestID)
	// No RealIP: it believed X-Forwarded-For, X-Real-IP and True-Client-IP from
	// anyone. The client address is the TCP peer's.
	r.Use(AccessLog(log))
	r.Use(middleware.Recoverer)
	r.Use(MetricsMiddleware)
}

// AccessLog logs each request through log, so LOG_LEVEL governs it like every other line.
// It names the route pattern, never the request URI: the path and the query carry SUPIs,
// GPSIs and other subscriber identifiers.
func AccessLog(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			next.ServeHTTP(ww, r)

			status := responseStatus(ww)
			level := accessLevel(status)
			if !log.Enabled(r.Context(), level) {
				return
			}
			log.LogAttrs(r.Context(), level, "SBI request",
				slog.String("method", r.Method),
				slog.String("route", getRoutePattern(r)),
				slog.Int("status", status),
				slog.Int("bytes", ww.BytesWritten()),
				slog.Duration("duration", time.Since(start)),
				slog.String("proto", r.Proto),
				slog.String("request_id", middleware.GetReqID(r.Context())),
				slog.String("peer", r.RemoteAddr),
			)
		})
	}
}

// accessLevel is the level of a request's access line: a line per request is for
// debugging, metrics count them; a 5xx is the gateway's or the back end's failure.
func accessLevel(status int) slog.Level {
	if status >= http.StatusInternalServerError {
		return slog.LevelWarn
	}
	return slog.LevelDebug
}

// responseStatus is the status the client got: a handler that never writes a header
// sends 200.
func responseStatus(ww middleware.WrapResponseWriter) int {
	if ww.Status() == 0 {
		return http.StatusOK
	}
	return ww.Status()
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
		status := strconv.Itoa(responseStatus(ww))
		path := getRoutePattern(r)

		metrics.RecordRequest(r.Method, path, status, duration)
	})
}

// unmatchedRoute names a request no route matched, in metric labels and access lines.
const unmatchedRoute = "unmatched"

// getRoutePattern extracts the chi route pattern for consistent metric labels.
// This prevents high cardinality from dynamic path segments like SUPI values.
// Example: /nudm-ueau/v1/imsi-123456789/auth-events -> /nudm-ueau/v1/{supiOrSuci}/auth-events
//
// A request no route matched is unmatchedRoute, not its path: the path is the client's
// choice, so it could carry a subscriber identifier into logs or a new label per request
// into the metrics.
func getRoutePattern(r *http.Request) string {
	rctx := chi.RouteContext(r.Context())
	if rctx == nil {
		return unmatchedRoute
	}

	// RoutePattern returns the template, e.g., /nudm-ueau/v1/{supiOrSuci}/auth-events
	pattern := rctx.RoutePattern()
	if pattern == "" {
		return unmatchedRoute
	}

	return pattern
}
