// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	sbiclient "github.com/3eAI-Labs/sbi-ha-gateway-client"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/models"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/nats"
	gnats "github.com/nats-io/nats.go"
)

// UE identifier formats of TS 29.571 (Supi, Suci, Gpsi, ExtGroupId). The specification's
// patterns also admit any other string; the gateway accepts only these, and only URI-safe
// characters in them: an escaped "/" inside an identifier must not shift the resource path
// the application receives.
var (
	// SUPI formats: imsi-<5-15 digits> or nai-<user@realm>
	supiIMSIPattern = regexp.MustCompile(`^imsi-[0-9]{5,15}$`)
	supiNAIPattern  = regexp.MustCompile(`^nai-[a-zA-Z0-9_.+-]+@[a-zA-Z0-9.-]+$`)

	// SUCI format: suci-<supiType>-<mcc>-<mnc>-<routingIndicator>-<protectionSchemeId>-<homeNetworkPublicKeyId>-<schemeOutput>
	// Example: suci-0-001-01-0000-0-0-0001010000
	suciPattern = regexp.MustCompile(`^suci-[0-9]-[0-9]{3}-[0-9]{2,3}-[0-9]{1,4}-[0-9]+-[0-9]+-[0-9A-Fa-f]+$`)

	gpsiPattern     = regexp.MustCompile(`^(msisdn-[0-9]{5,15}|extid-[A-Za-z0-9._~+-]+@[A-Za-z0-9.-]+)$`)
	extGroupPattern = regexp.MustCompile(`^extgroupid-[A-Za-z0-9._~+-]+@[A-Za-z0-9.-]+$`)
)

// UeIDKinds is the set of UE identifier kinds a URI variable accepts.
type UeIDKinds uint8

const (
	IDSUPI UeIDKinds = 1 << iota
	IDSUCI
	IDGPSI
	IDExtGroup
	IDAnyUE // the literal "anyUE" (Nudm_EE)
)

func (k UeIDKinds) match(v string) bool {
	return k&IDSUPI != 0 && (supiIMSIPattern.MatchString(v) || supiNAIPattern.MatchString(v)) ||
		k&IDSUCI != 0 && suciPattern.MatchString(v) ||
		k&IDGPSI != 0 && gpsiPattern.MatchString(v) ||
		k&IDExtGroup != 0 && extGroupPattern.MatchString(v) ||
		k&IDAnyUE != 0 && v == "anyUE"
}

func (k UeIDKinds) String() string {
	var names []string
	for _, n := range []struct {
		k    UeIDKinds
		name string
	}{{IDSUPI, "a SUPI"}, {IDSUCI, "a SUCI"}, {IDGPSI, "a GPSI"}, {IDExtGroup, "an External Group Id"}, {IDAnyUE, `"anyUE"`}} {
		if k&n.k != 0 {
			names = append(names, n.name)
		}
	}
	return strings.Join(names, " or ")
}

type BaseHandler struct {
	Log            *slog.Logger
	RequestTimeout time.Duration
}

// DefaultRequestTimeout is used when no timeout is configured
const DefaultRequestTimeout = 2 * time.Second

func (h *BaseHandler) WriteProblem(w http.ResponseWriter, status int, cause string, detail string) {
	h.writeProblemBody(w, status, models.ProblemDetails{
		Status: status,
		Title:  http.StatusText(status),
		Cause:  cause,
		Detail: detail,
	})
}

func (h *BaseHandler) writeProblemBody(w http.ResponseWriter, status int, prob interface{}) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(prob); err != nil {
		// Can't write problem response, just log (avoid recursion)
		if h.Log != nil {
			h.Log.Error("Failed to encode problem response", slog.Any("error", err))
		}
		metrics.RecordError("encode", "problem_response_failed")
	}
}

func (h *BaseHandler) WriteJSON(w http.ResponseWriter, status int, v interface{}) {
	if status == http.StatusNoContent {
		// No body: net/http refuses one with 204 (ErrBodyNotAllowed).
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		if h.Log != nil {
			h.Log.Error("Failed to encode JSON response", slog.Any("error", err))
		}
		metrics.RecordError("encode", "json_response_failed")
	}
}

// MaxRequestBodyBytes bounds a request body. Registrations, events and subscriber data
// are a few kilobytes; a larger body is refused with 413 before it is read further.
const MaxRequestBodyBytes = 1 << 20

// DecodeBody decodes the request body into v. A body over MaxRequestBodyBytes is
// answered 413, one that is not JSON 400 INVALID_MSG_FORMAT (TS 29.500 Table
// 5.2.7.2-1); DecodeBody then returns false.
func (h *BaseHandler) DecodeBody(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)).Decode(v)
	if err == nil {
		return true
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		h.WriteProblem(w, http.StatusRequestEntityTooLarge, "",
			fmt.Sprintf("Request body larger than %d bytes", tooLarge.Limit))
		return false
	}
	h.WriteProblem(w, http.StatusBadRequest, "INVALID_MSG_FORMAT", err.Error())
	return false
}

// MarshalRequest marshals a backend request payload to JSON.
// On failure it writes an RFC 7807 problem response and returns ok=false,
// so callers can early-return without a separate error branch.
// Named to avoid the json.Marshaler.MarshalJSON signature collision.
func (h *BaseHandler) MarshalRequest(w http.ResponseWriter, v interface{}) ([]byte, bool) {
	data, err := json.Marshal(v)
	if err != nil {
		h.Log.Error("JSON marshal failed", slog.Any("error", err))
		metrics.RecordError("marshal", "json_marshal_failed")
		h.WriteProblem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", "Failed to encode request")
		return nil, false
	}
	return data, true
}

// Exchange sends req to the application on subject and handles its reply. It returns true
// when the application answered with its result, decoded into v (nil: the result is not
// read). Otherwise it has answered the network function and returns false.
func (h *BaseHandler) Exchange(w http.ResponseWriter, r *http.Request, nc nats.INatsClient, subject string, req, v interface{}) bool {
	data, ok := h.MarshalRequest(w, req)
	if !ok {
		return false
	}
	reply, err := nc.Request(r.Context(), subject, data, h.RequestTimeout)
	if err != nil {
		h.WriteRequestFailure(w, err)
		return false
	}
	return h.DecodeReply(w, reply, v)
}

// WriteRequestFailure answers a NATS request that brought no application reply (TS 29.500
// Table 5.2.7.2-1 causes). A reply from JetStream means a stream captures the request
// subject: the back end is misconfigured and waiting would not help, so it is 500. No
// reply in time, no application subscribed or no NATS connection is 504: the network
// function may try another producer.
func (h *BaseHandler) WriteRequestFailure(w http.ResponseWriter, err error) {
	if h.Log != nil {
		h.Log.Error("NATS request failed", slog.Any("error", err))
	}
	switch {
	case errors.Is(err, nats.ErrJetStreamReply):
		h.WriteProblem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", "Invalid response from backend")
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, gnats.ErrTimeout):
		h.WriteProblem(w, http.StatusGatewayTimeout, "TARGET_NF_NOT_REACHABLE", "No reply from the back end in time")
	case errors.Is(err, gnats.ErrNoResponders):
		h.WriteProblem(w, http.StatusGatewayTimeout, "TARGET_NF_NOT_REACHABLE", "No back end serves the request")
	default:
		h.WriteProblem(w, http.StatusGatewayTimeout, "TARGET_NF_NOT_REACHABLE", "Back end not reachable")
	}
}

// DecodeReply handles an application's reply. It must be a JSON object; json.Unmarshal
// would also take null into a struct, and the network function would get an empty result
// as a success. An ErrorReply is passed to the network function with its status. Neither:
// the reply is decoded into v (nil: not read) and DecodeReply returns true. Otherwise it
// has answered the network function and returns false.
func (h *BaseHandler) DecodeReply(w http.ResponseWriter, data []byte, v interface{}) bool {
	var envelope struct {
		ProblemDetails *sbiclient.ProblemDetails `json:"problemDetails"`
	}
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' || json.Unmarshal(data, &envelope) != nil {
		h.writeInvalidReply(w, "not a JSON object", len(data))
		return false
	}
	if p := envelope.ProblemDetails; p != nil {
		if p.Status < 400 || p.Status > 599 {
			h.writeInvalidReply(w, "problemDetails without a 4xx or 5xx status", len(data))
			return false
		}
		h.writeProblemBody(w, p.Status, p)
		return false
	}
	if v != nil && json.Unmarshal(data, v) != nil {
		h.writeInvalidReply(w, "not the operation's result", len(data))
		return false
	}
	return true
}

func (h *BaseHandler) writeInvalidReply(w http.ResponseWriter, reason string, size int) {
	if h.Log != nil {
		h.Log.Error("Invalid reply from back end", slog.String("reason", reason), slog.Int("bytes", size))
	}
	h.WriteProblem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", "Invalid response from backend")
}

// ValidateUeID checks the UE identifier in URI variable variable (as the specification
// names it, "{supi}") against the kinds the operation accepts. Otherwise it writes 400
// MANDATORY_IE_INCORRECT with the variable in invalidParams (TS 29.500 Table 5.2.7.2-1,
// TS 29.571 InvalidParam) and returns false.
func (h *BaseHandler) ValidateUeID(w http.ResponseWriter, value, variable string, kinds UeIDKinds) bool {
	if kinds.match(value) {
		return true
	}
	h.WriteInvalidParam(w, variable, "must be "+kinds.String())
	return false
}

// WriteInvalidParam answers 400 MANDATORY_IE_INCORRECT for URI variable variable (TS
// 29.500 Table 5.2.7.2-1), named in invalidParams as TS 29.571 asks: "{pduSessionId}".
func (h *BaseHandler) WriteInvalidParam(w http.ResponseWriter, variable, reason string) {
	h.writeProblemBody(w, http.StatusBadRequest, models.ProblemDetails{
		Status:        http.StatusBadRequest,
		Title:         http.StatusText(http.StatusBadRequest),
		Cause:         "MANDATORY_IE_INCORRECT",
		Detail:        variable + " " + reason,
		InvalidParams: []models.InvalidParam{{Param: variable, Reason: reason}},
	})
}

// RoutedPath is the path chi matched the route on: RawPath when the request had escaped
// characters, else Path. URL parameters come from it, so a resource computed by trimming
// them must start from it too.
func RoutedPath(r *http.Request) string {
	if r.URL.RawPath != "" {
		return r.URL.RawPath
	}
	return r.URL.Path
}

// SafeResource reports whether a resource path, as routed, names nothing but itself: no
// empty, "." or ".." segment and no escaped "/", decoded or not.
func SafeResource(resource string) bool {
	if resource == "" {
		return true
	}
	for _, segment := range strings.Split(resource, "/") {
		s, err := url.PathUnescape(segment)
		if err != nil || s == "" || s == "." || s == ".." || strings.Contains(s, "/") {
			return false
		}
	}
	return true
}

// ResourceURI is the absolute URI of the request's resource, plus suffix: the Location
// of a resource the request created.
func ResourceURI(r *http.Request, suffix string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.EscapedPath() + suffix
}
