// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	sbiclient "github.com/3eAI-Labs/sbi-ha-gateway-client"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/audit"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/nats"
	"github.com/go-chi/chi/v5"
)

type MobilityHandler struct {
	BaseHandler
	Nats nats.INatsClient
}

func NewMobilityHandler(log *slog.Logger, nc nats.INatsClient, requestTimeout time.Duration) *MobilityHandler {
	if requestTimeout == 0 {
		requestTimeout = DefaultRequestTimeout
	}
	return &MobilityHandler{
		BaseHandler: BaseHandler{Log: log, RequestTimeout: requestTimeout},
		Nats:        nc,
	}
}

// Nudm_UECM (TS 29.503 Table 6.2.3.1-1). {ueId} is a SUPI for PUT, PATCH and DELETE, a
// SUPI or a GPSI for GET.
func (h *MobilityHandler) RegisterRoutes(r chi.Router) {
	r.Route("/nudm-uecm/v1/{ueId}/registrations", func(r chi.Router) {
		r.Get("/", h.get(""))
		r.Route("/amf-3gpp-access", func(r chi.Router) {
			r.Get("/", h.get("amf-3gpp-access"))
			r.Put("/", h.RegisterAmf)
			r.Patch("/", h.UpdateAmf)
		})
		r.Get("/smf-registrations", h.get("smf-registrations"))
		r.Route("/smf-registrations/{pduSessionId}", func(r chi.Router) {
			r.Get("/", h.get("smf-registrations/{pduSessionId}"))
			r.Put("/", h.RegisterSmf)
			r.Patch("/", h.UpdateSmf)
			r.Delete("/", h.DeregisterSmf)
		})
		r.Route("/smsf-3gpp-access", func(r chi.Router) {
			r.Get("/", h.get("smsf-3gpp-access"))
			r.Put("/", h.RegisterSmsf)
			r.Delete("/", h.DeregisterSmsf)
		})
	})
}

// supi reads {ueId} for a PUT, PATCH or DELETE, which take a SUPI only.
func (h *MobilityHandler) supi(w http.ResponseWriter, r *http.Request) (string, bool) {
	supi := chi.URLParam(r, "ueId")
	return supi, h.ValidateUeID(w, supi, "{ueId}", IDSUPI)
}

// pduSessionID reads {pduSessionId}: an integer 0-255 (TS 29.571 PduSessionId), in its
// plain decimal form.
func (h *MobilityHandler) pduSessionID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := chi.URLParam(r, "pduSessionId")
	if n, err := strconv.Atoi(id); err != nil || n < 0 || n > 255 || strconv.Itoa(n) != id {
		h.WriteInvalidParam(w, "{pduSessionId}", "must be an integer from 0 to 255")
		return "", false
	}
	return id, true
}

// get answers a GET from the registration store: resource is the path after
// .../registrations, with {pduSessionId} filled in.
func (h *MobilityHandler) get(resource string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ueID := chi.URLParam(r, "ueId")
		if !h.ValidateUeID(w, ueID, "{ueId}", IDSUPI|IDGPSI) {
			return
		}
		res := resource
		if strings.Contains(res, "{pduSessionId}") {
			id, ok := h.pduSessionID(w, r)
			if !ok {
				return
			}
			res = strings.Replace(res, "{pduSessionId}", id, 1)
		}
		natsReq := sbiclient.MobilityQuery{
			UeId:     ueID,
			Resource: res,
			Query:    r.URL.RawQuery,
		}
		var result map[string]json.RawMessage
		if !h.Exchange(w, r, h.Nats, sbiclient.SubjectMobilityQuery, natsReq, &result) {
			return
		}
		h.WriteJSON(w, http.StatusOK, result)
	}
}

// change sends one registration change and reports whether the application accepted it,
// with its reply.
func (h *MobilityHandler) change(w http.ResponseWriter, r *http.Request, req sbiclient.MobilityRequest, body interface{}) (sbiclient.MobilityReply, bool) {
	var reply sbiclient.MobilityReply
	if body != nil {
		raw, ok := h.MarshalRequest(w, body)
		if !ok {
			return reply, false
		}
		req.Data = raw
	}
	ok := h.Exchange(w, r, h.Nats, sbiclient.SubjectMobilityRegistration, req, &reply)
	return reply, ok
}

// writePut answers a PUT that the application accepted (TS 29.503): 200 with the
// registration when it replaced one, else 201 with the registration and its URI.
func (h *MobilityHandler) writePut(w http.ResponseWriter, r *http.Request, reply sbiclient.MobilityReply, registration interface{}) {
	if reply.Updated {
		h.WriteJSON(w, http.StatusOK, registration)
		return
	}
	w.Header().Set("Location", ResourceURI(r, ""))
	h.WriteJSON(w, http.StatusCreated, registration)
}

// --- AMF registration (3GPP access): PUT, PATCH ---

func (h *MobilityHandler) RegisterAmf(w http.ResponseWriter, r *http.Request) {
	supi, ok := h.supi(w, r)
	if !ok {
		return
	}
	var reg sbiclient.Amf3GppAccessRegistration
	if !h.DecodeBody(w, r, &reg) {
		return
	}
	reply, ok := h.change(w, r, sbiclient.MobilityRequest{Supi: supi, Op: sbiclient.OpRegister}, reg)
	if !ok {
		return
	}
	audit.Log(r, "REGISTER_AMF", "nudm-uecm", supi, reg)
	h.writePut(w, r, reply, reg)
}

func (h *MobilityHandler) UpdateAmf(w http.ResponseWriter, r *http.Request) {
	supi, ok := h.supi(w, r)
	if !ok {
		return
	}
	// Amf3GppAccessRegistrationModification, passed on as the network function sent it.
	var updates map[string]interface{}
	if !h.DecodeBody(w, r, &updates) {
		return
	}
	if _, ok := h.change(w, r, sbiclient.MobilityRequest{Supi: supi, Op: sbiclient.OpUpdate}, updates); !ok {
		return
	}
	audit.Log(r, "UPDATE_AMF", "nudm-uecm", supi, updates)
	h.WriteJSON(w, http.StatusNoContent, nil)
}

// --- SMF registration (per PDU session): PUT, PATCH, DELETE ---

func (h *MobilityHandler) RegisterSmf(w http.ResponseWriter, r *http.Request) {
	h.smfOp(w, r, sbiclient.OpRegister)
}

func (h *MobilityHandler) UpdateSmf(w http.ResponseWriter, r *http.Request) {
	h.smfOp(w, r, sbiclient.OpUpdate)
}

func (h *MobilityHandler) DeregisterSmf(w http.ResponseWriter, r *http.Request) {
	h.smfOp(w, r, sbiclient.OpDeregister)
}

func (h *MobilityHandler) smfOp(w http.ResponseWriter, r *http.Request, op string) {
	supi, ok := h.supi(w, r)
	if !ok {
		return
	}
	pduSessionID, ok := h.pduSessionID(w, r)
	if !ok {
		return
	}
	req := sbiclient.MobilityRequest{
		Supi:         supi,
		Op:           op,
		Nf:           sbiclient.NfSMF,
		PduSessionId: pduSessionID,
	}
	body, ok := h.registrationBody(w, r, op, &sbiclient.SmfRegistration{})
	if !ok {
		return
	}
	reply, ok := h.change(w, r, req, body)
	if !ok {
		return
	}

	// AUDIT: SMF registration changes are state-changing.
	audit.Log(r, op+"_SMF", "nudm-uecm", supi, body)
	h.writeChange(w, r, op, reply, body)
}

// --- SMSF registration (3GPP access): PUT, DELETE ---

func (h *MobilityHandler) RegisterSmsf(w http.ResponseWriter, r *http.Request) {
	h.smsfOp(w, r, sbiclient.OpRegister)
}

func (h *MobilityHandler) DeregisterSmsf(w http.ResponseWriter, r *http.Request) {
	h.smsfOp(w, r, sbiclient.OpDeregister)
}

func (h *MobilityHandler) smsfOp(w http.ResponseWriter, r *http.Request, op string) {
	supi, ok := h.supi(w, r)
	if !ok {
		return
	}
	req := sbiclient.MobilityRequest{Supi: supi, Op: op, Nf: sbiclient.NfSMSF}
	body, ok := h.registrationBody(w, r, op, &sbiclient.SmsfRegistration{})
	if !ok {
		return
	}
	reply, ok := h.change(w, r, req, body)
	if !ok {
		return
	}

	// AUDIT: SMSF registration changes are state-changing.
	audit.Log(r, op+"_SMSF", "nudm-uecm", supi, body)
	h.writeChange(w, r, op, reply, body)
}

// registrationBody decodes the request body: the registration into reg for a PUT, the
// modification object as sent for a PATCH, nothing for a DELETE.
func (h *MobilityHandler) registrationBody(w http.ResponseWriter, r *http.Request, op string, reg interface{}) (interface{}, bool) {
	switch op {
	case sbiclient.OpRegister:
		return reg, h.DecodeBody(w, r, reg)
	case sbiclient.OpUpdate:
		var updates map[string]interface{}
		ok := h.DecodeBody(w, r, &updates)
		return updates, ok
	}
	return nil, true
}

func (h *MobilityHandler) writeChange(w http.ResponseWriter, r *http.Request, op string, reply sbiclient.MobilityReply, body interface{}) {
	if op == sbiclient.OpRegister {
		h.writePut(w, r, reply, body)
		return
	}
	h.WriteJSON(w, http.StatusNoContent, nil)
}
