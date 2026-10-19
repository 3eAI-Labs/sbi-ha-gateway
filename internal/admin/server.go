// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package admin

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/nats"
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type AdminServer struct {
	Nats nats.INatsClient

	draining atomic.Bool
	checks   []func() bool // more conditions of readiness; added before serving
}

// AddReadinessCheck adds a condition /health/ready requires. Call it before the server serves.
func (s *AdminServer) AddReadinessCheck(ready func() bool) {
	s.checks = append(s.checks, ready)
}

func (s *AdminServer) ready() bool {
	if s.draining.Load() || s.Nats == nil || !s.Nats.IsConnected() {
		return false
	}
	for _, check := range s.checks {
		if !check() {
			return false
		}
	}
	return true
}

func NewAdminServer(nc nats.INatsClient) *AdminServer {
	return &AdminServer{Nats: nc}
}

// Drain makes the readiness probe fail from now on: the gateway is shutting down and
// still serves while whatever routes to it learns that it should stop.
func (s *AdminServer) Drain() {
	s.draining.Store(true)
}

func (s *AdminServer) SetupRouter() *chi.Mux {
	r := chi.NewRouter()

	// Metrics
	r.Handle("/metrics", promhttp.Handler())

	// Health
	r.Get("/health/live", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r.Get("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		if s.ready() {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})

	// Stats
	r.Get("/admin/stats", func(w http.ResponseWriter, r *http.Request) {
		stats := map[string]interface{}{
			"nats_connected": s.Nats.IsConnected(),
			"service":        "sbi-ha-gateway",
		}
		// A failed write means the caller has gone; there is no one left to tell.
		_ = json.NewEncoder(w).Encode(stats)
	})

	return r
}

// HTTPServer returns the admin port's server. Its timeouts keep a slow or idle client
// from holding a connection: the port has no authentication.
func (s *AdminServer) HTTPServer(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s.SetupRouter(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}
