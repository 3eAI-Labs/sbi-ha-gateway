// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package admin

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"errors"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/nats"
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"os"
)

type AdminServer struct {
	Nats nats.INatsClient
	// Log receives the readiness changes; nil: slog.Default().
	Log *slog.Logger

	draining atomic.Bool
	checks   []readinessCheck // more conditions of readiness; added before serving
	token    *TokenFile       // bearer token of /metrics and /admin/*; nil: open

	mu        sync.Mutex
	lastState string // reasons of the last readiness answer, for logging its changes
}

type readinessCheck struct {
	name  string
	ready func() bool
}

func NewAdminServer(nc nats.INatsClient) *AdminServer {
	return &AdminServer{Nats: nc, lastState: "unknown"}
}

// Drain makes the readiness probe fail from now on: the gateway is shutting down and
// still serves while whatever routes to it learns that it should stop.
func (s *AdminServer) Drain() {
	s.draining.Store(true)
}

// AddReadinessCheck adds a condition /health/ready requires; name is the reason given while it
// is false. Call it before the server serves.
func (s *AdminServer) AddReadinessCheck(name string, ready func() bool) {
	s.checks = append(s.checks, readinessCheck{name: name, ready: ready})
}

// RequireToken makes /metrics and /admin/* answer only requests carrying
// "Authorization: Bearer <token>". The health endpoints stay open: the kubelet probes them
// without credentials. Call it before the server serves.
func (s *AdminServer) RequireToken(token *TokenFile) {
	s.token = token
}

// tokenReread is how long a token read from its file is used before the file is read again.
const tokenReread = 10 * time.Second

// TokenFile is the admin bearer token, read from its file and again at most every
// tokenReread: a rotated Secret takes effect without a restart. When the file cannot be read
// later, the last token read stays in force.
type TokenFile struct {
	path   string
	mu     sync.Mutex
	token  []byte
	readAt time.Time
}

// NewTokenFile reads path: a file that cannot be read, or is empty, is an error.
func NewTokenFile(path string) (*TokenFile, error) {
	t := &TokenFile{path: path}
	if err := t.read(time.Now()); err != nil {
		return nil, err
	}
	return t, nil
}

// read reads the token, without its trailing newline. Called with mu held, or before use.
func (t *TokenFile) read(now time.Time) error {
	t.readAt = now
	data, err := os.ReadFile(t.path) // #nosec G304 -- ADMIN_TOKEN_FILE, the operator's setting
	if err != nil {
		return err
	}
	token := []byte(strings.TrimRight(string(data), "\r\n"))
	if len(token) == 0 {
		return errors.New("empty")
	}
	t.token = token
	return nil
}

func (t *TokenFile) current(now time.Time) []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	if now.Sub(t.readAt) >= tokenReread {
		_ = t.read(now)
	}
	return t.token
}

// notReady lists why the gateway is not ready; none when it is.
func (s *AdminServer) notReady() []string {
	var reasons []string
	if s.draining.Load() {
		reasons = append(reasons, "draining")
	}
	if s.Nats == nil || !s.Nats.IsConnected() {
		reasons = append(reasons, "nats_disconnected")
	}
	for _, check := range s.checks {
		if !check.ready() {
			reasons = append(reasons, check.name)
		}
	}
	return reasons
}

// logChange logs readiness when it differs from the last answer: probes come every few
// seconds, a line each would drown the log.
func (s *AdminServer) logChange(reasons []string) {
	state := strings.Join(reasons, ",")
	s.mu.Lock()
	changed := state != s.lastState
	s.lastState = state
	s.mu.Unlock()
	if !changed {
		return
	}
	log := s.Log
	if log == nil {
		log = slog.Default()
	}
	if len(reasons) == 0 {
		log.Info("Ready")
		return
	}
	log.Warn("Not ready", slog.Any("reasons", reasons))
}

// authorized wraps next with the bearer token check, when there is a token.
func (s *AdminServer) authorized(next http.Handler) http.Handler {
	if s.token == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), s.token.current(time.Now())) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="sbi-ha-gateway admin"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *AdminServer) SetupRouter() *chi.Mux {
	r := chi.NewRouter()

	// Metrics
	r.Handle("/metrics", s.authorized(promhttp.Handler()))

	// Health
	r.Get("/health/live", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r.Get("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		reasons := s.notReady()
		s.logChange(reasons)
		w.Header().Set("Content-Type", "application/json")
		if len(reasons) > 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ready": len(reasons) == 0, "reasons": reasons})
	})

	// Stats
	r.Method(http.MethodGet, "/admin/stats", s.authorized(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stats := map[string]interface{}{
			"nats_connected": s.Nats.IsConnected(),
			"service":        "sbi-ha-gateway",
		}
		// A failed write means the caller has gone; there is no one left to tell.
		_ = json.NewEncoder(w).Encode(stats)
	})))

	return r
}

// HTTPServer returns the admin port's server. Its timeouts keep a slow or idle client
// from holding a connection.
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
