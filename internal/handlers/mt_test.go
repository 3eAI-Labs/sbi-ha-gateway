// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package handlers_test

import (
	"bytes"
	"encoding/json"
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

func TestMTHandler_ProvideLocInfo_Success(t *testing.T) {
	// Setup
	mockNats := new(MockNatsClient)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	h := handlers.NewMTHandler(logger, mockNats, 0)

	// Router setup to capture URL params
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	// Request Payload
	reqBody := sbiclient.ProvideLocInfoRequest{
		ReqCurrentLoc: true,
	}
	body, _ := json.Marshal(reqBody)

	// Expected NATS Response
	natsResp := sbiclient.ProvideLocInfoResult{
		CurrentLoc: true,
		Supi:       "imsi-123456789012345",
		Location: &sbiclient.UserLocation{
			NrLocation: &sbiclient.NrLocation{
				Tai: &sbiclient.Tai{
					PlmnId: &sbiclient.PlmnId{Mcc: "123", Mnc: "45"},
					Tac:    "123456",
				},
			},
		},
	}
	natsRespBytes, _ := json.Marshal(natsResp)

	// Mock NATS Expectation (uses default timeout of 2s)
	mockNats.On("Request", mock.Anything, "5g.mt.loc-info", mock.Anything, handlers.DefaultRequestTimeout).
		Return(natsRespBytes, nil)

	// Perform Request
	req := httptest.NewRequest(http.MethodPost, "/nudm-mt/v1/imsi-123456789012345/loc-info/provide-loc-info", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var resp sbiclient.ProvideLocInfoResult
	assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	assert.Equal(t, "imsi-123456789012345", resp.Supi)
	assert.NotNil(t, resp.Location.NrLocation)
	mockNats.AssertExpectations(t)
}

func TestMTHandler_ProvideLocInfo_InvalidJSON(t *testing.T) {
	mockNats := new(MockNatsClient)
	h := handlers.NewMTHandler(nil, mockNats, 0)
	r := chi.NewRouter()
	h.RegisterRoutes(r)
	req := httptest.NewRequest(http.MethodPost, "/nudm-mt/v1/imsi-123456789012345/loc-info/provide-loc-info", bytes.NewBufferString("invalid"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMTHandler_ProvideLocInfo_InvalidResponse(t *testing.T) {
	mockNats := new(MockNatsClient)
	h := handlers.NewMTHandler(slog.New(slog.NewJSONHandler(os.Stdout, nil)), mockNats, 0)
	r := chi.NewRouter()
	h.RegisterRoutes(r)
	mockNats.On("Request", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]byte("invalid"), nil)
	body, _ := json.Marshal(sbiclient.ProvideLocInfoRequest{})
	req := httptest.NewRequest(http.MethodPost, "/nudm-mt/v1/imsi-123456789012345/loc-info/provide-loc-info", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
