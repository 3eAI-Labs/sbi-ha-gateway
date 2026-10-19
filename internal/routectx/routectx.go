// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

// Package routectx carries the route a request matched, in the specification's terms
// ("/nudm-sdm/v2/{supi}/am-data"), from the handler that knows it to the middleware that
// labels metrics and access lines after the handler has run.
package routectx

import (
	"context"
	"net/http"
)

type holder struct{ route string }

type key struct{}

// Middleware gives each request a place for its route. It must run before the middleware
// that reads the route.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), key{}, &holder{})))
	})
}

// Set records r's route. Without Middleware it does nothing.
func Set(r *http.Request, route string) {
	if h, ok := r.Context().Value(key{}).(*holder); ok {
		h.route = route
	}
}

// Get returns the route Set recorded for r, or "".
func Get(r *http.Request) string {
	if h, ok := r.Context().Value(key{}).(*holder); ok {
		return h.route
	}
	return ""
}
