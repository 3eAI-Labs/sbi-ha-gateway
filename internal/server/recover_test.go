// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/models"
	"github.com/go-chi/chi/v5"
	dto "github.com/prometheus/client_model/go"
)

func requestsCounted(t *testing.T, method, path, status string) float64 {
	t.Helper()
	var m dto.Metric
	if err := metrics.RequestsTotal.WithLabelValues(method, path, status).Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

// A handler's panic is answered 500 SYSTEM_FAILURE as ProblemDetails, counted as that 500,
// and logged as one line with its stack. 0.2.x answered an empty 500, counted nothing and
// wrote the stack to stderr as text (A.10).
func TestRecover_Panic(t *testing.T) {
	var logs bytes.Buffer
	r := chi.NewRouter()
	RegisterMiddleware(r, slog.New(slog.NewJSONHandler(&logs, nil)))
	r.Get("/boom", func(http.ResponseWriter, *http.Request) { panic("handler bug") })
	before := requestsCounted(t, "GET", "/boom", "500")

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))

	var pd models.ProblemDetails
	if err := json.Unmarshal(rec.Body.Bytes(), &pd); err != nil || rec.Code != 500 ||
		rec.Header().Get("Content-Type") != "application/problem+json" || pd.Cause != "SYSTEM_FAILURE" || pd.Status != 500 {
		t.Errorf("%d %q %s", rec.Code, rec.Header().Get("Content-Type"), rec.Body)
	}
	if after := requestsCounted(t, "GET", "/boom", "500"); after != before+1 {
		t.Errorf("requests_total{GET,/boom,500} %v → %v, want one more", before, after)
	}
	var line struct {
		Msg, Panic, Route, Stack string
	}
	for _, l := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if strings.Contains(l, "Handler panicked") {
			_ = json.Unmarshal([]byte(l), &line)
		}
	}
	if line.Panic != "handler bug" || line.Route != "/boom" || !strings.Contains(line.Stack, "recover_test.go") {
		t.Errorf("log line %+v", line)
	}
}

// After the response began, a 500 cannot follow: the stream is aborted. http.ErrAbortHandler
// from a handler is passed on as it is.
func TestRecover_AbortsStartedResponse(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"panic after the status": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			panic("late bug")
		},
		"ErrAbortHandler": func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) },
	} {
		t.Run(name, func(t *testing.T) {
			h := Recover(slog.New(slog.DiscardHandler))(handler)
			defer func() {
				if rvr := recover(); rvr != http.ErrAbortHandler { //nolint:errorlint // the recovered value
					t.Errorf("recovered %v, want http.ErrAbortHandler", rvr)
				}
			}()
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
			t.Error("no panic")
		})
	}
}
