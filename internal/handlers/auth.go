// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package handlers

import (
	"log/slog"
	"net/http"
	"net/url"
	"time"

	sbiclient "github.com/3eAI-Labs/sbi-ha-gateway-client"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/audit"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/nats"
	"github.com/go-chi/chi/v5"
)

type AuthHandler struct {
	BaseHandler
	Nats nats.INatsClient
}

func NewAuthHandler(log *slog.Logger, nc nats.INatsClient, requestTimeout time.Duration) *AuthHandler {
	if requestTimeout == 0 {
		requestTimeout = DefaultRequestTimeout
	}
	return &AuthHandler{
		BaseHandler: BaseHandler{Log: log, RequestTimeout: requestTimeout},
		Nats:        nc,
	}
}

func (h *AuthHandler) RegisterRoutes(r chi.Router) {
	// One URI variable for both routes, so chi can match them; it is {supiOrSuci} for
	// generate-auth-data and {supi} for auth-events in TS 29.503.
	r.Route("/nudm-ueau/v1/{ueId}", func(r chi.Router) {
		r.Post("/security-information/generate-auth-data", h.GenerateAuthData)
		r.Post("/auth-events", h.ConfirmAuth)
	})
}

func (h *AuthHandler) GenerateAuthData(w http.ResponseWriter, r *http.Request) {
	supiOrSuci := chi.URLParam(r, "ueId")
	if !h.ValidateUeID(w, supiOrSuci, "{supiOrSuci}", IDSUPI|IDSUCI) {
		return
	}

	var req sbiclient.AuthenticationInfoRequest
	if !h.DecodeBody(w, r, &req) {
		return
	}

	natsReq := sbiclient.AuthRequest{Supi: supiOrSuci, AuthenticationInfoRequest: req}

	var result sbiclient.AuthenticationInfoResult
	if !h.Exchange(w, r, h.Nats, sbiclient.SubjectAuthRequest, natsReq, &result) {
		return
	}

	// AUDIT: state-changing. Payload sanitiser strips the
	// auth vector fields (rand, autn, kausf, xresStar) before emission.
	audit.Log(r, "GENERATE_AUTH_DATA", "nudm-ueau", supiOrSuci, req)

	h.WriteJSON(w, http.StatusOK, result)
}

// ConfirmAuth stores the AUSF's authentication result: 201 with the event and its URI,
// .../auth-events/{authEventId}, the identifier the UDM assigned (TS 29.503).
func (h *AuthHandler) ConfirmAuth(w http.ResponseWriter, r *http.Request) {
	supi := chi.URLParam(r, "ueId")
	if !h.ValidateUeID(w, supi, "{supi}", IDSUPI) {
		return
	}

	var event sbiclient.AuthEvent
	if !h.DecodeBody(w, r, &event) {
		return
	}

	natsReq := sbiclient.AuthConfirmRequest{Supi: supi, Event: event}

	var reply sbiclient.AuthConfirmReply
	if !h.Exchange(w, r, h.Nats, sbiclient.SubjectAuthConfirm, natsReq, &reply) {
		return
	}
	if reply.AuthEventId == "" {
		h.writeInvalidReply(w, "no authEventId", 0)
		return
	}

	// AUDIT: confirms successful auth. Sanitiser strips xresStar.
	audit.Log(r, "CONFIRM_AUTH", "nudm-ueau", supi, event)

	w.Header().Set("Location", ResourceURI(r, "/"+url.PathEscape(reply.AuthEventId)))
	h.WriteJSON(w, http.StatusCreated, event)
}
