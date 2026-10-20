// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	sbiclient "github.com/3eAI-Labs/sbi-ha-gateway-client"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/audit"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/nats"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/routectx"
	"github.com/go-chi/chi/v5"
)

// varKind is how the gateway checks a path variable before the application sees it.
type varKind uint8

const (
	varSegment      varKind = iota // one URI segment, for the application to interpret
	varUE                          // a UE identifier of the kinds in specVar.UE
	varPduSessionID                // TS 29.571 PduSessionId: an integer 0-255
)

// specVar is a path variable, under the name the specification gives it.
type specVar struct {
	Name string
	Kind varKind
	UE   UeIDKinds
}

// locRule is how a 201 gets its Location.
type locRule uint8

const (
	locNone       locRule = iota // the 201 carries no Location
	locRequestURI                // the request URI is the created resource
	locChild                     // <request URI>/<Reply.ResourceId>
)

// specOperation is one operation of an API's OpenAPI definition (operations_gen.go).
type specOperation struct {
	API, Version, Method, Path, OperationID string
	Vars                                    []specVar
	// Success is the success statuses the specification allows.
	Success  []int
	Location locRule
	// Accepts is the request body's media types; none: the operation takes no body.
	Accepts      []string
	BodyRequired bool
}

// subject is the NATS subject the operation goes to. Subjects are the NATS permission
// boundaries: what returns authentication vectors goes to SubjectAuthRequest alone.
func (op *specOperation) subject() string {
	switch op.API {
	case sbiclient.ServiceNudmUEAU:
		if op.OperationID == "ConfirmAuth" || op.OperationID == "DeleteAuth" {
			return sbiclient.SubjectAuthConfirm
		}
		return sbiclient.SubjectAuthRequest
	case sbiclient.ServiceNudmUECM:
		if op.Method == http.MethodGet || op.OperationID == "SendRoutingInfoSm" {
			return sbiclient.SubjectMobilityQuery
		}
		return sbiclient.SubjectMobilityRegistration
	case sbiclient.ServiceNudmMT:
		return sbiclient.SubjectLocationInfo
	}
	if op.Method == http.MethodGet {
		return sbiclient.SubjectDataQuery
	}
	return sbiclient.SubjectDataUpdate
}

// status is the status the reply asks for, if the operation allows it. 0 stands for the
// operation's only success status.
func (op *specOperation) status(s int) (int, bool) {
	if s == 0 {
		if len(op.Success) == 1 {
			return op.Success[0], true
		}
		return 0, false
	}
	return s, slices.Contains(op.Success, s)
}

// SBIHandler serves every operation in specOperations. It checks the request URI and body
// against the specification, hands the operation to the application as an
// sbiclient.Request and answers the network function from the application's
// sbiclient.Reply or ErrorReply. It does not interpret bodies: the specification's data
// types are the contract between the network function and the application.
type SBIHandler struct {
	BaseHandler
	Nats nats.INatsClient
	// apis maps each API name to the version the gateway serves.
	apis map[string]string
}

func NewSBIHandler(log *slog.Logger, nc nats.INatsClient, requestTimeout time.Duration) *SBIHandler {
	if requestTimeout == 0 {
		requestTimeout = DefaultRequestTimeout
	}
	apis := map[string]string{}
	for _, op := range specOperations {
		apis[op.API] = op.Version
	}
	return &SBIHandler{
		BaseHandler: BaseHandler{Log: log, RequestTimeout: requestTimeout},
		Nats:        nc,
		apis:        apis,
	}
}

// RegisterRoutes routes every operation, and answers what matches none with ProblemDetails
// (TS 29.500 Table 5.2.7.2-1).
//
// chi needs variables at the same place in two routes to have the same name, and the
// specification names them per operation ({supi}, {ueId}, {supiOrSuci}), so each is routed
// as {s<segment index>}; the handler maps it back.
func (h *SBIHandler) RegisterRoutes(r chi.Router) {
	for i := range specOperations {
		op := &specOperations[i]
		segments := strings.Split(op.Path, "/")
		var at []int
		for j, s := range segments {
			if strings.HasPrefix(s, "{") {
				segments[j] = "{s" + strconv.Itoa(j) + "}"
				at = append(at, j)
			}
		}
		r.MethodFunc(op.Method, "/"+op.API+"/"+op.Version+strings.Join(segments, "/"), h.serve(op, at))
	}
	r.NotFound(h.notFound)
	r.MethodNotAllowed(func(w http.ResponseWriter, req *http.Request) {
		for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodPost, http.MethodPatch, http.MethodDelete} {
			if r.Match(chi.NewRouteContext(), m, RoutedPath(req)) {
				w.Header().Add("Allow", m)
			}
		}
		h.WriteProblem(w, http.StatusMethodNotAllowed, "", "Method not allowed on this resource")
	})
}

// apiNamePattern is the shape of an SBI API name (TS 29.501 clause 4.4.1).
var apiNamePattern = regexp.MustCompile(`^n[a-z0-9]+-[a-z0-9-]+$`)

// notFound answers a request no route matched: 400 INVALID_API for an API or API version
// the gateway does not serve, 404 RESOURCE_URI_STRUCTURE_NOT_FOUND for an unknown resource
// of one it does.
func (h *SBIHandler) notFound(w http.ResponseWriter, r *http.Request) {
	segments := strings.SplitN(strings.TrimPrefix(RoutedPath(r), "/"), "/", 3)
	version, served := h.apis[segments[0]]
	switch {
	case served && len(segments) > 1 && segments[1] == version:
		h.WriteProblem(w, http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND", "No such resource")
	case served:
		h.WriteProblem(w, http.StatusBadRequest, "INVALID_API",
			fmt.Sprintf("API version not served; %s is served as %s", segments[0], version))
	case apiNamePattern.MatchString(segments[0]):
		h.WriteProblem(w, http.StatusBadRequest, "INVALID_API", "API not served")
	default:
		h.WriteProblem(w, http.StatusNotFound, "", "No such resource")
	}
}

// serve handles op; at is the segment index of each of op.Vars in op.Path.
func (h *SBIHandler) serve(op *specOperation, at []int) http.HandlerFunc {
	route := "/" + op.API + "/" + op.Version + op.Path
	prefix := "/" + op.API + "/" + op.Version
	return func(w http.ResponseWriter, r *http.Request) {
		routectx.Set(r, route)

		// A state-changing operation is audited however it ends — refused by the gateway or
		// the application, failed, or done — with the operation and the (masked) subscriber,
		// never the body: the gateway does not interpret bodies, so it cannot tell key
		// material from the rest (Nudr authentication-subscription carries encPermanentKey,
		// and in a JSON Patch the secret sits under "value").
		var ueID string
		if op.Method != http.MethodGet {
			rec := audit.NewRecorder(w)
			w = rec
			defer func() { audit.Request(r, op.OperationID, op.API, ueID, rec.Status(), rec.Cause()) }()
		}

		params, id, ok := h.params(w, r, op, at)
		ueID = id
		if !ok {
			return
		}
		contentType, body, ok := h.body(w, r, op)
		if !ok {
			return
		}
		req := sbiclient.Request{
			Service:     op.API,
			Operation:   op.OperationID,
			Method:      op.Method,
			Path:        strings.TrimPrefix(r.URL.EscapedPath(), prefix),
			Params:      params,
			Query:       r.URL.RawQuery,
			ContentType: contentType,
			Body:        body,
		}

		var reply sbiclient.Reply
		if !h.Exchange(w, r, h.Nats, op.subject(), req, &reply) {
			return
		}
		status, ok := op.status(reply.Status)
		if !ok {
			h.writeInvalidReply(w, fmt.Sprintf("status %d not allowed for %s", reply.Status, op.OperationID), 0)
			return
		}
		if status != http.StatusNoContent && !jsonDocument(reply.Body) {
			h.writeInvalidReply(w, "no response body", len(reply.Body))
			return
		}
		if status == http.StatusCreated {
			switch op.Location {
			case locRequestURI:
				w.Header().Set("Location", ResourceURI(r, ""))
			case locChild:
				id := reply.ResourceId
				if id == "" || id == "." || id == ".." || strings.Contains(id, "/") {
					h.writeInvalidReply(w, "no resourceId for the created resource", 0)
					return
				}
				w.Header().Set("Location", ResourceURI(r, "/"+url.PathEscape(id)))
			}
		}

		if status == http.StatusNoContent {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(reply.Body) // a failed write means the network function has gone
	}
}

// params checks op's path variables and returns them by their specification names, decoded,
// with the first UE identifier among them. Otherwise it has answered and returns false.
func (h *SBIHandler) params(w http.ResponseWriter, r *http.Request, op *specOperation, at []int) (map[string]string, string, bool) {
	if len(op.Vars) == 0 {
		return nil, "", true
	}
	params := make(map[string]string, len(op.Vars))
	var ueID string
	for i, v := range op.Vars {
		raw := chi.URLParam(r, "s"+strconv.Itoa(at[i]))
		variable := "{" + v.Name + "}"
		switch v.Kind {
		case varUE:
			if !h.ValidateUeID(w, raw, variable, v.UE) {
				return nil, "", false
			}
			if ueID == "" {
				ueID = raw
			}
		case varPduSessionID:
			if n, err := strconv.Atoi(raw); err != nil || n < 0 || n > 255 || strconv.Itoa(n) != raw {
				h.WriteInvalidParam(w, variable, "must be an integer from 0 to 255")
				return nil, "", false
			}
		default:
			if raw == "" || !SafeResource(raw) {
				h.WriteProblem(w, http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND", "No such resource")
				return nil, "", false
			}
		}
		value, err := url.PathUnescape(raw)
		if err != nil {
			h.WriteProblem(w, http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND", "No such resource")
			return nil, "", false
		}
		params[v.Name] = value
	}
	return params, ueID, true
}

// body reads the request body of an operation that takes one: at most
// MaxRequestBodyBytes (else 413), of a media type the operation accepts (else 415), a JSON
// object or array (else 400 INVALID_MSG_FORMAT), present when the specification requires
// it. Otherwise it has answered and returns false.
func (h *SBIHandler) body(w http.ResponseWriter, r *http.Request, op *specOperation) (string, json.RawMessage, bool) {
	if len(op.Accepts) == 0 {
		return "", nil, true
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			h.WriteProblem(w, http.StatusRequestEntityTooLarge, "",
				fmt.Sprintf("Request body larger than %d bytes", tooLarge.Limit))
			return "", nil, false
		}
		h.WriteProblem(w, http.StatusBadRequest, "INVALID_MSG_FORMAT", "Request body could not be read")
		return "", nil, false
	}
	if len(bytes.TrimSpace(data)) == 0 {
		if op.BodyRequired {
			h.WriteProblem(w, http.StatusBadRequest, "INVALID_MSG_FORMAT", "Request body required")
			return "", nil, false
		}
		return "", nil, true
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !slices.Contains(op.Accepts, mediaType) {
		h.WriteProblem(w, http.StatusUnsupportedMediaType, "",
			"Content-Type must be "+strings.Join(op.Accepts, " or "))
		return "", nil, false
	}
	if !jsonDocument(data) {
		h.WriteProblem(w, http.StatusBadRequest, "INVALID_MSG_FORMAT", "Request body is not a JSON object or array")
		return "", nil, false
	}
	return mediaType, data, true
}

// jsonDocument reports whether data is a JSON object or array: what every body of these
// APIs is, and what null, a number or a string is not.
func jsonDocument(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') && json.Valid(trimmed)
}
