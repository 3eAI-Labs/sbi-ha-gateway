// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package handlers

import (
	"log/slog"
	"net/http"
	"time"

	sbiclient "github.com/3eAI-Labs/sbi-ha-gateway-client"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/audit"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/nats"
	"github.com/go-chi/chi/v5"
)

type MTHandler struct {
	BaseHandler
	Nats nats.INatsClient
}

func NewMTHandler(log *slog.Logger, nc nats.INatsClient, requestTimeout time.Duration) *MTHandler {
	if requestTimeout == 0 {
		requestTimeout = DefaultRequestTimeout
	}
	return &MTHandler{
		BaseHandler: BaseHandler{Log: log, RequestTimeout: requestTimeout},
		Nats:        nc,
	}
}

func (h *MTHandler) RegisterRoutes(r chi.Router) {
	r.Route("/nudm-mt/v1/{supi}", func(r chi.Router) {
		r.Post("/loc-info/provide-loc-info", h.ProvideLocInfo)
	})
}

func (h *MTHandler) ProvideLocInfo(w http.ResponseWriter, r *http.Request) {
	supi := chi.URLParam(r, "supi")
	if !h.ValidateUeID(w, supi, "{supi}", IDSUPI) {
		return
	}

	var req sbiclient.ProvideLocInfoRequest
	if !h.DecodeBody(w, r, &req) {
		return
	}

	natsReq := sbiclient.LocationInfoRequest{Supi: supi, Req: req}

	var result sbiclient.ProvideLocInfoResult
	if !h.Exchange(w, r, h.Nats, sbiclient.SubjectLocationInfo, natsReq, &result) {
		return
	}

	audit.Log(r, "PROVIDE_LOC_INFO", "nudm-mt", supi, req)

	h.WriteJSON(w, http.StatusOK, result)
}
