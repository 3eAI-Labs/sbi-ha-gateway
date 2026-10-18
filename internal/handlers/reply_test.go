// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package handlers_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/models"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// A reply that is not a JSON object is not the application's: json.Unmarshal takes null
// into a struct without error, and the network function would get an empty success.
func TestHandlers_ReplyNotAnObject(t *testing.T) {
	for _, c := range itCalls {
		for _, reply := range []string{`null`, ``, ` `, `[]`, `"ok"`, `1`, `true`, `{`} {
			rec := serveWithReply(reply, c.method, c.path, c.body)
			assertProblem(t, rec, http.StatusInternalServerError, "SYSTEM_FAILURE", c.method+" "+c.path+" replying "+reply)
		}
	}
}

// An ErrorReply reaches the network function with its own status and body.
func TestHandlers_ErrorReply(t *testing.T) {
	const problem = `{"status":503,"cause":"NF_CONGESTION","title":"Service Unavailable"}`
	for _, c := range itCalls {
		rec := serveWithReply(`{"problemDetails":`+problem+`}`, c.method, c.path, c.body)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code, "%s %s", c.method, c.path)
		assert.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
		assert.JSONEq(t, problem, rec.Body.String(), "%s %s", c.method, c.path)
	}
}

// An ErrorReply whose status is not an HTTP error is not a valid reply.
func TestHandlers_ErrorReplyWithoutErrorStatus(t *testing.T) {
	for _, reply := range []string{
		`{"problemDetails":{}}`,
		`{"problemDetails":{"cause":"USER_NOT_FOUND"}}`,
		`{"problemDetails":{"status":200}}`,
		`{"problemDetails":{"status":399}}`,
		`{"problemDetails":{"status":600}}`,
		`{"problemDetails":{"status":"404"}}`,
		`{"problemDetails":"USER_NOT_FOUND"}`,
	} {
		for _, c := range itCalls {
			rec := serveWithReply(reply, c.method, c.path, c.body)
			assertProblem(t, rec, http.StatusInternalServerError, "SYSTEM_FAILURE", c.method+" "+c.path+" replying "+reply)
		}
	}
}

// A JSON object that does not decode into the operation's result is not a valid reply.
func TestHandlers_ReplyNotTheResult(t *testing.T) {
	gen := itCalls[0]
	rec := serveWithReply(`{"authVector":"r"}`, gen.method, gen.path, gen.body)
	assertProblem(t, rec, http.StatusInternalServerError, "SYSTEM_FAILURE", "generate-auth-data")
}

func TestDataHandler_Result(t *testing.T) {
	rec := serveWithReply(`{"payload":{"a":1}}`, "GET", "/nudr-dr/v1/subscription-data/"+itSupi+"/am-data", "")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"a":1}`, rec.Body.String())
}

func serveWithReply(reply, method, path, body string) *httptest.ResponseRecorder {
	mockNats := new(MockNatsClient)
	mockNats.On("Request", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]byte(reply), nil)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := chi.NewRouter()
	handlers.NewAuthHandler(log, mockNats, 0).RegisterRoutes(r)
	handlers.NewMobilityHandler(log, mockNats, 0).RegisterRoutes(r)
	handlers.NewMTHandler(log, mockNats, 0).RegisterRoutes(r)
	handlers.NewDataHandler(log, mockNats, 0).RegisterRoutes(r)

	var rd io.Reader
	if body != "" {
		rd = bytes.NewBufferString(body)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(method, path, rd))
	return rec
}

// A body over the limit is refused with 413, one that is not JSON with 400
// INVALID_MSG_FORMAT; neither reaches NATS (the mock has no expectation, so a request
// would fail the test).
func TestHandlers_RequestBody(t *testing.T) {
	huge := `{"a":"` + strings.Repeat("x", handlers.MaxRequestBodyBytes) + `"}`
	for _, c := range itCalls {
		if c.body == "" {
			continue
		}
		for _, tc := range []struct {
			body   string
			status int
			cause  string
		}{
			{huge, http.StatusRequestEntityTooLarge, ""},
			{`{"servingNetworkName":`, http.StatusBadRequest, "INVALID_MSG_FORMAT"},
		} {
			mockNats := new(MockNatsClient)
			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			r := chi.NewRouter()
			handlers.NewAuthHandler(log, mockNats, 0).RegisterRoutes(r)
			handlers.NewMobilityHandler(log, mockNats, 0).RegisterRoutes(r)
			handlers.NewMTHandler(log, mockNats, 0).RegisterRoutes(r)
			handlers.NewDataHandler(log, mockNats, 0).RegisterRoutes(r)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, bytes.NewBufferString(tc.body)))
			assertProblem(t, rec, tc.status, tc.cause, fmt.Sprintf("%s %s with a %d-byte body", c.method, c.path, len(tc.body)))
			mockNats.AssertNotCalled(t, "Request")
		}
	}
}

// Each URI variable takes the identifier kinds its specification names; any other is 400
// MANDATORY_IE_INCORRECT naming the variable (TS 29.500, TS 29.571 InvalidParam).
func TestHandlers_UeIdentifiers(t *testing.T) {
	const (
		supi  = "imsi-001010000000001"
		suci  = "suci-0-001-01-0000-0-0-0001010000"
		gpsi  = "msisdn-491711234567"
		group = "extgroupid-fleet@operator.example"
	)
	for _, c := range []struct {
		method, path, body string
		variable           string // "" when accepted
	}{
		{"POST", "/nudm-ueau/v1/" + suci + "/security-information/generate-auth-data", `{}`, ""},
		{"POST", "/nudm-ueau/v1/" + gpsi + "/security-information/generate-auth-data", `{}`, "{supiOrSuci}"},
		{"POST", "/nudm-ueau/v1/" + suci + "/auth-events", `{}`, "{supi}"},
		{"PUT", "/nudm-uecm/v1/" + gpsi + "/registrations/amf-3gpp-access", `{}`, "{ueId}"},
		{"GET", "/nudm-uecm/v1/" + gpsi + "/registrations/amf-3gpp-access", ``, ""},
		{"GET", "/nudm-uecm/v1/" + suci + "/registrations", ``, "{ueId}"},
		{"POST", "/nudm-mt/v1/" + gpsi + "/loc-info/provide-loc-info", `{}`, "{supi}"},
		{"GET", "/nudm-sdm/v1/" + gpsi + "/am-data", ``, "{supi}"},
		{"GET", "/nudm-pp/v1/" + group + "/pp-data", ``, ""},
		{"GET", "/nudm-pp/v1/anyUE/pp-data", ``, "{ueId}"},
		{"POST", "/nudm-ee/v1/" + supi + "/ee-subscriptions", `{}`, "{ueIdentity}"},
		{"GET", "/nudr-dr/v1/subscription-data/" + gpsi + "/context-data", ``, ""},
		{"GET", "/nudr-dr/v1/subscription-data/" + group + "/context-data", ``, "{ueId}"},
	} {
		var body io.Reader
		if c.body != "" {
			body = bytes.NewBufferString(c.body)
		}
		mockNats := new(MockNatsClient)
		mockNats.On("Request", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]byte(`{"authEventId":"1"}`), nil)
		log := slog.New(slog.NewTextHandler(io.Discard, nil))
		r := chi.NewRouter()
		handlers.NewAuthHandler(log, mockNats, 0).RegisterRoutes(r)
		handlers.NewMobilityHandler(log, mockNats, 0).RegisterRoutes(r)
		handlers.NewMTHandler(log, mockNats, 0).RegisterRoutes(r)
		handlers.NewDataHandler(log, mockNats, 0).RegisterRoutes(r)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, body))
		msg := c.method + " " + c.path
		if c.variable == "" {
			assert.Less(t, rec.Code, 300, "%s: %s", msg, rec.Body.String())
			continue
		}
		assertProblem(t, rec, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", msg)
		var prob models.ProblemDetails
		if assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &prob)) && assert.Len(t, prob.InvalidParams, 1, msg) {
			assert.Equal(t, c.variable, prob.InvalidParams[0].Param, msg)
		}
		mockNats.AssertNotCalled(t, "Request")
	}
}

// Nothing in a URI may make the application read another resource than the one routed:
// an encoded slash inside an identifier, dot segments in the path, or a PDU session ID
// that is not 0-255 (TS 29.571 PduSessionId).
func TestHandlers_PathConfusion(t *testing.T) {
	for _, c := range []struct {
		method, path    string
		status          int
		cause, variable string
	}{
		{"GET", "/nudr-dr/v1/subscription-data/extid-a%2F..%2F..%2Fx@d/context-data", http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "{ueId}"},
		{"GET", "/nudm-ee/v1/extgroupid-a%2F..@d/ee-subscriptions", http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "{ueIdentity}"},
		{"GET", "/nudr-dr/v1/subscription-data/imsi-001010000000001/../../policy-data/x", http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND", ""},
		{"GET", "/nudm-sdm/v1/imsi-001010000000001/sdm-subscriptions/./x", http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND", ""},
		{"GET", "/nudm-uecm/v1/imsi-001010000000001/registrations/smf-registrations/256", http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "{pduSessionId}"},
		{"PUT", "/nudm-uecm/v1/imsi-001010000000001/registrations/smf-registrations/a", http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "{pduSessionId}"},
		{"DELETE", "/nudm-uecm/v1/imsi-001010000000001/registrations/smf-registrations/5%2F..%2Fx", http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "{pduSessionId}"},
		// An empty identifier on a route that has one is not "no identifier".
		{"GET", "/nudr-dr/v1/subscription-data//context-data", http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "{ueId}"},
		{"GET", "/nudm-pp/v1//pp-data", http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "{ueId}"},
		{"POST", "/nudm-ee/v1//ee-subscriptions", http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "{ueIdentity}"},
		{"GET", "/nudm-sdm/v1//am-data", http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "{supi}"},
		{"GET", "/nudr-dr/v1/subscription-data/imsi-001010000000001/context-data//x", http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND", ""},
	} {
		mockNats := new(MockNatsClient)
		log := slog.New(slog.NewTextHandler(io.Discard, nil))
		r := chi.NewRouter()
		handlers.NewMobilityHandler(log, mockNats, 0).RegisterRoutes(r)
		handlers.NewDataHandler(log, mockNats, 0).RegisterRoutes(r)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, bytes.NewBufferString(`{}`)))
		msg := c.method + " " + c.path
		assertProblem(t, rec, c.status, c.cause, msg)
		if c.variable != "" {
			var prob models.ProblemDetails
			if assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &prob)) && assert.Len(t, prob.InvalidParams, 1, msg) {
				assert.Equal(t, c.variable, prob.InvalidParams[0].Param, msg)
			}
		}
		mockNats.AssertNotCalled(t, "Request")
	}
}
