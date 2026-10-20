// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	gnats "github.com/nats-io/nats.go"
)

// In a NATS outage every request fails: one error line per failureLogInterval, with how many
// went unreported, the request ID and the subject; the others at debug (C.2). 0.3.0 wrote an
// error line per request, without either.
func TestWriteRequestFailure_RateLimited(t *testing.T) {
	var logs strings.Builder
	h := &BaseHandler{Log: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))}
	for i := range 50 {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r = r.WithContext(context.WithValue(r.Context(), middleware.RequestIDKey, "req-"+string(rune('a'+i%26))))
		w := httptest.NewRecorder()
		h.WriteRequestFailure(w, r, "5g.data.query", gnats.ErrNoResponders)
		if w.Code != http.StatusGatewayTimeout {
			t.Fatalf("status %d", w.Code)
		}
	}
	if n := strings.Count(logs.String(), "NATS request failed"); n != 1 {
		t.Errorf("%d error lines for 50 failures, want 1:\n%s", n, logs.String())
	}
	if !strings.Contains(logs.String(), "subject=5g.data.query") || !strings.Contains(logs.String(), "request_id=req-a") {
		t.Errorf("line lacks subject or request ID: %s", logs.String())
	}
}

func TestFailureLog_Interval(t *testing.T) {
	var f failureLog
	now := time.Now()
	if log, n := f.report(now); !log || n != 0 {
		t.Errorf("first: %v %d", log, n)
	}
	for range 7 {
		if log, _ := f.report(now.Add(time.Second)); log {
			t.Error("logged inside the interval")
		}
	}
	if log, n := f.report(now.Add(failureLogInterval)); !log || n != 7 {
		t.Errorf("after the interval: %v, %d unreported, want true, 7", log, n)
	}
}
