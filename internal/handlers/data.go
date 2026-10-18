// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	sbiclient "github.com/3eAI-Labs/sbi-ha-gateway-client"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/nats"
	"github.com/go-chi/chi/v5"
)

type DataHandler struct {
	BaseHandler
	Nats nats.INatsClient
}

func NewDataHandler(log *slog.Logger, nc nats.INatsClient, requestTimeout time.Duration) *DataHandler {
	if requestTimeout == 0 {
		requestTimeout = DefaultRequestTimeout
	}
	return &DataHandler{
		BaseHandler: BaseHandler{Log: log, RequestTimeout: requestTimeout},
		Nats:        nc,
	}
}

// dataRoute is one family of data routes: its API, the name the specification gives its
// UE identifier variable, and the identifier kinds it accepts there.
type dataRoute struct {
	service  string
	variable string
	kinds    UeIDKinds
}

func (h *DataHandler) RegisterRoutes(r chi.Router) {
	// Nudr_DataRepository (TS 29.505): {ueId} is a SUPI or a GPSI.
	nudr := h.handle(dataRoute{sbiclient.ServiceNudrDR, "{ueId}", IDSUPI | IDGPSI})
	r.Route("/nudr-dr/v1/{dataSet}", func(r chi.Router) {
		r.Get("/shared-data", nudr)
		r.Get("/shared-data/{sharedDataId}", nudr)
		r.Get("/{ueId}", nudr)
		r.HandleFunc("/{ueId}/*", nudr)
	})

	// Nudm_SDM: {supi}.
	sdm := h.handle(dataRoute{sbiclient.ServiceNudmSDM, "{supi}", IDSUPI})
	r.Route("/nudm-sdm/v1", func(r chi.Router) {
		r.Get("/shared-data", sdm)
		r.Get("/{ueId}", sdm)
		r.Get("/{ueId}/{sdmDataSet}", sdm)
		r.HandleFunc("/{ueId}/sdm-subscriptions*", sdm)
	})

	// Nudm_PP: {ueId} is a GPSI, a SUPI or an External Group Id.
	r.HandleFunc("/nudm-pp/v1/{ueId}/pp-data",
		h.handle(dataRoute{sbiclient.ServiceNudmPP, "{ueId}", IDSUPI | IDGPSI | IDExtGroup}))

	// Nudm_EE: {ueIdentity} is a GPSI, an External Group Id or "anyUE".
	r.HandleFunc("/nudm-ee/v1/{ueId}/ee-subscriptions*",
		h.handle(dataRoute{sbiclient.ServiceNudmEE, "{ueIdentity}", IDGPSI | IDExtGroup | IDAnyUE}))
}

func (h *DataHandler) handle(rt dataRoute) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.forward(w, r, rt)
	}
}

// forward sends one call of a data service as a DataRequest. Resource is the URI path
// after the UE identifier, or after the API version (Nudr: the data set) when there is
// none.
func (h *DataHandler) forward(w http.ResponseWriter, r *http.Request, rt dataRoute) {
	dataSet := chi.URLParam(r, "dataSet")
	// A route with {ueId} needs a valid one: chi matches an empty segment ("//") too, and
	// an empty identifier must not pass for the shared-data routes' absent one.
	ueID := chi.URLParam(r, "ueId")
	if strings.Contains(chi.RouteContext(r.Context()).RoutePattern(), "{ueId}") &&
		!h.ValidateUeID(w, ueID, rt.variable, rt.kinds) {
		return
	}
	resource, ok := strings.CutPrefix(RoutedPath(r), "/"+rt.service+"/v1/")
	for _, segment := range []string{dataSet, ueID} {
		if ok && segment != "" {
			resource, ok = strings.CutPrefix(resource, segment)
			resource = strings.TrimPrefix(resource, "/")
		}
	}
	if !ok || !SafeResource(dataSet) || !SafeResource(resource) {
		h.WriteProblem(w, http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND", "No such resource")
		return
	}

	var payload json.RawMessage
	if r.Method == http.MethodPut || r.Method == http.MethodPatch || r.Method == http.MethodPost {
		if !h.DecodeBody(w, r, &payload) {
			return
		}
	}

	natsReq := sbiclient.DataRequest{
		Service:  rt.service,
		UeId:     ueID,
		DataSet:  dataSet,
		Resource: resource,
		Method:   r.Method,
		Query:    r.URL.RawQuery,
		Payload:  payload,
	}

	// Dynamic subject based on operation
	subject := sbiclient.SubjectDataQuery
	if r.Method != http.MethodGet {
		subject = sbiclient.SubjectDataUpdate
	}

	var result sbiclient.DataResponse
	if !h.Exchange(w, r, h.Nats, subject, natsReq, &result) {
		return
	}

	h.WriteJSON(w, http.StatusOK, result.Payload)
}
