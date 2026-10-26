// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"log/slog"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/oauth"
	"github.com/go-chi/chi/v5"
)

type RouterConfig struct {
	// SBI serves the Nudm and Nudr operations.
	SBI *handlers.SBIHandler

	// OAuthValidator authenticates incoming SBI requests via NRF-issued
	// access tokens. nil disables OAuth (development mode).
	OAuthValidator oauth.Validator

	// RateLimitRPS sets the per-NF token-bucket refill rate. 0 disables limiting.
	RateLimitRPS   float64
	RateLimitBurst int

	// Logger receives the access lines; nil means slog.Default().
	Logger *slog.Logger

	// NRFNotifications mounts the callback of the gateway's NRF subscriptions; nil: none.
	// Its path needs no access token (oauth.RequiredScope).
	NRFNotifications func(chi.Router)
}

func NewRouter(cfg RouterConfig) *chi.Mux {
	r := chi.NewRouter()

	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	RegisterMiddleware(r, log)
	// PeerIdentityMiddleware MUST run before OAuth so the validator can
	// read the peer cert thumbprint for RFC 8705 binding. h2c / non-mTLS
	// connections result in a no-op — chain stays correct in both modes.
	r.Use(PeerIdentityMiddleware)
	// OAuth runs BEFORE the rate limiter so the limiter can use the
	// authenticated `sub` claim as its key — see nfKey() in ratelimit.go.
	r.Use(OAuthMiddleware(cfg.OAuthValidator))
	r.Use(NFRateLimitMiddleware(cfg.RateLimitRPS, cfg.RateLimitBurst))

	if cfg.NRFNotifications != nil {
		cfg.NRFNotifications(r)
	}
	if cfg.SBI != nil {
		cfg.SBI.RegisterRoutes(r)
	}

	return r
}
