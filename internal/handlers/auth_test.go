// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package handlers_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	sbiclient "github.com/3eAI-Labs/sbi-ha-gateway-client"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAuthHandler_GenerateAuthData_Success(t *testing.T) {
	mockNats := new(MockNatsClient)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	h := handlers.NewAuthHandler(logger, mockNats, 0)

	r := chi.NewRouter()
	h.RegisterRoutes(r)

	reqBody := sbiclient.AuthenticationInfoRequest{
		ServingNetworkName: "5G:mnc045.mcc123.3gppnetwork.org",
		AusfInstanceId:     "ausf-1",
	}
	body, _ := json.Marshal(reqBody)

	natsResp := sbiclient.AuthenticationInfoResult{
		Supi: "imsi-12345",
		AuthVector: &sbiclient.AuthenticationVector{
			Rand: "rand",
			Autn: "autn",
		},
	}
	natsRespBytes, _ := json.Marshal(natsResp)

	mockNats.On("Request", mock.Anything, "5g.auth.request", mock.Anything, handlers.DefaultRequestTimeout).
		Return(natsRespBytes, nil)

	req := httptest.NewRequest(http.MethodPost, "/nudm-ueau/v1/imsi-12345/security-information/generate-auth-data", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp sbiclient.AuthenticationInfoResult
	assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "imsi-12345", resp.Supi)
	mockNats.AssertExpectations(t)
}

func TestAuthHandler_ConfirmAuth_Success(t *testing.T) {
	mockNats := new(MockNatsClient)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	h := handlers.NewAuthHandler(logger, mockNats, 0)

	r := chi.NewRouter()
	h.RegisterRoutes(r)

	event := sbiclient.AuthEvent{
		Success:      true,
		NfInstanceId: "ausf-1",
	}
	body, _ := json.Marshal(event)

	mockNats.On("Request", mock.Anything, "5g.auth.confirm", mock.Anything, handlers.DefaultRequestTimeout).
		Return([]byte(`{"authEventId":"ev 1"}`), nil)

	req := httptest.NewRequest(http.MethodPost, "/nudm-ueau/v1/imsi-12345/auth-events", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	// TS 29.503: 201, the created AuthEvent, and its URI with the authEventId the UDM gave.
	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "http://example.com/nudm-ueau/v1/imsi-12345/auth-events/ev%201", w.Header().Get("Location"))
	assert.JSONEq(t, string(body), w.Body.String())
	mockNats.AssertExpectations(t)
}

// Without the authEventId there is no URI for the event: the reply is not the result.
func TestAuthHandler_ConfirmAuth_ReplyWithoutAuthEventId(t *testing.T) {
	mockNats := new(MockNatsClient)
	mockNats.On("Request", mock.Anything, "5g.auth.confirm", mock.Anything, mock.Anything).Return([]byte(`{}`), nil)
	r := chi.NewRouter()
	handlers.NewAuthHandler(nil, mockNats, 0).RegisterRoutes(r)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/nudm-ueau/v1/imsi-12345/auth-events",
		bytes.NewBufferString(`{"nfInstanceId":"ausf-1","success":true}`)))
	assertProblem(t, w, http.StatusInternalServerError, "SYSTEM_FAILURE", "auth-events replying {}")
}

func TestAuthHandler_GenerateAuthData_InvalidJSON(t *testing.T) {
	mockNats := new(MockNatsClient)
	h := handlers.NewAuthHandler(nil, mockNats, 0)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	req := httptest.NewRequest(http.MethodPost, "/nudm-ueau/v1/imsi-123456789012345/security-information/generate-auth-data", bytes.NewBufferString("invalid json"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_GenerateAuthData_InvalidNatsResponse(t *testing.T) {
	mockNats := new(MockNatsClient)
	h := handlers.NewAuthHandler(slog.New(slog.NewJSONHandler(os.Stdout, nil)), mockNats, 0)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	body, _ := json.Marshal(sbiclient.AuthenticationInfoRequest{})
	mockNats.On("Request", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]byte("invalid json"), nil)

	req := httptest.NewRequest(http.MethodPost, "/nudm-ueau/v1/imsi-123456789012345/security-information/generate-auth-data", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAuthHandler_ConfirmAuth_InvalidJSON(t *testing.T) {
	mockNats := new(MockNatsClient)
	h := handlers.NewAuthHandler(nil, mockNats, 0)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	req := httptest.NewRequest(http.MethodPost, "/nudm-ueau/v1/imsi-123456789012345/auth-events", bytes.NewBufferString("invalid json"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_ConfirmAuth_NatsError(t *testing.T) {
	mockNats := new(MockNatsClient)
	h := handlers.NewAuthHandler(slog.New(slog.NewJSONHandler(os.Stdout, nil)), mockNats, 0)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	body, _ := json.Marshal(sbiclient.AuthEvent{})
	mockNats.On("Request", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]byte(nil), errors.New("error"))

	req := httptest.NewRequest(http.MethodPost, "/nudm-ueau/v1/imsi-123456789012345/auth-events", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusGatewayTimeout, w.Code)
}

func TestAuthHandler_GenerateAuthData_InvalidSUPI(t *testing.T) {
	mockNats := new(MockNatsClient)
	h := handlers.NewAuthHandler(slog.New(slog.NewJSONHandler(os.Stdout, nil)), mockNats, 0)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	body, _ := json.Marshal(sbiclient.AuthenticationInfoRequest{})

	// Test with invalid SUPI (no prefix, too short)
	req := httptest.NewRequest(http.MethodPost, "/nudm-ueau/v1/12345/security-information/generate-auth-data", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Verify NATS was never called (validation failed early)
	mockNats.AssertNotCalled(t, "Request")
}

func TestAuthHandler_GenerateAuthData_ValidSUCI(t *testing.T) {
	mockNats := new(MockNatsClient)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	h := handlers.NewAuthHandler(logger, mockNats, 0)

	r := chi.NewRouter()
	h.RegisterRoutes(r)

	body, _ := json.Marshal(sbiclient.AuthenticationInfoRequest{})
	natsResp := sbiclient.AuthenticationInfoResult{Supi: "imsi-123456789012345"}
	natsRespBytes, _ := json.Marshal(natsResp)

	mockNats.On("Request", mock.Anything, "5g.auth.request", mock.Anything, handlers.DefaultRequestTimeout).
		Return(natsRespBytes, nil)

	// Valid SUCI format
	req := httptest.NewRequest(http.MethodPost, "/nudm-ueau/v1/suci-0-001-01-0000-0-0-0001010000/security-information/generate-auth-data", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockNats.AssertExpectations(t)
}

// The AUSF's whole request body reaches the application, re-synchronisation info among
// it (TS 29.503 ResynchronizationInfo: rand and auts).
func TestAuthHandler_GenerateAuthData_ForwardsRequestBody(t *testing.T) {
	mockNats := new(MockNatsClient)
	var sent []byte
	mockNats.On("Request", mock.Anything, "5g.auth.request", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { sent = args.Get(2).([]byte) }).
		Return([]byte(`{"authVector":{"rand":"r","autn":"a","xresStar":"x","kAusf":"k"}}`), nil)
	r := chi.NewRouter()
	handlers.NewAuthHandler(nil, mockNats, 0).RegisterRoutes(r)

	body := `{"servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org","ausfInstanceId":"ausf-1",` +
		`"resynchronizationInfo":{"rand":"0011","auts":"2233"},"supportedFeatures":"1","cellCagInfo":["cag-1"],"nswoInd":true}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost,
		"/nudm-ueau/v1/imsi-001010000000001/security-information/generate-auth-data", bytes.NewBufferString(body)))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"supi":"imsi-001010000000001","servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org",`+
		`"ausfInstanceId":"ausf-1","resynchronizationInfo":{"rand":"0011","auts":"2233"},"supportedFeatures":"1",`+
		`"cellCagInfo":["cag-1"],"nswoInd":true}`, string(sent))
}
