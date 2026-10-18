// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package handlers_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	sbiclient "github.com/3eAI-Labs/sbi-ha-gateway-client"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/mock"
)

func BenchmarkAuthHandler_GenerateAuthData(b *testing.B) {
	mockNats := new(MockNatsClient)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
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
	}
	natsRespBytes, _ := json.Marshal(natsResp)

	mockNats.On("Request", mock.Anything, "5g.auth.request", mock.Anything, handlers.DefaultRequestTimeout).
		Return(natsRespBytes, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/nudm-ueau/v1/imsi-12345/security-information/generate-auth-data", bytes.NewBuffer(body))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
	}
}

func BenchmarkDataHandler_HandleGenericRequest(b *testing.B) {
	mockNats := new(MockNatsClient)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	h := handlers.NewDataHandler(logger, mockNats, 0)

	r := chi.NewRouter()
	h.RegisterRoutes(r)

	natsResp := sbiclient.DataResponse{
		Payload: json.RawMessage(`{"data":"value"}`),
	}
	respBytes, _ := json.Marshal(natsResp)

	mockNats.On("Request", mock.Anything, mock.Anything, mock.Anything, handlers.DefaultRequestTimeout).
		Return(respBytes, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/nudr-dr/v1/subscription-data/imsi-123/authentication-data", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
	}
}
