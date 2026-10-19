// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package handlers_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/mock"
)

// benchmark serves method path (with body) b.N times against an application that answers
// reply, and fails unless each request gets want: a benchmark of an error path measures
// nothing useful.
func benchmark(b *testing.B, method, path, body, reply string, want int) {
	mockNats := new(MockNatsClient)
	mockNats.On("Request", mock.Anything, mock.Anything, mock.Anything, handlers.DefaultRequestTimeout).
		Return([]byte(reply), nil)
	r := chi.NewRouter()
	handlers.NewSBIHandler(slog.New(slog.NewJSONHandler(io.Discard, nil)), mockNats, 0).RegisterRoutes(r)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != want {
			b.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body)
		}
	}
}

func BenchmarkSBI_GenerateAuthData(b *testing.B) {
	benchmark(b, http.MethodPost, "/nudm-ueau/v1/imsi-001010000000001/security-information/generate-auth-data",
		`{"servingNetworkName":"5G:mnc045.mcc123.3gppnetwork.org","ausfInstanceId":"ausf-1"}`,
		`{"body":{"authType":"5G_AKA","authenticationVector":{"avType":"5G_HE_AKA","rand":"r","xresStar":"x","autn":"a","kausf":"k"}}}`,
		http.StatusOK)
}

func BenchmarkSBI_GetAmData(b *testing.B) {
	benchmark(b, http.MethodGet, "/nudm-sdm/v2/imsi-001010000000001/am-data", "",
		`{"body":{"gpsis":["msisdn-905551112233"]}}`, http.StatusOK)
}
