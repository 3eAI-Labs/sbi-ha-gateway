// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	cgaudit "github.com/3eAI-Labs/sbi-ha-gateway/internal/platform/audit"
	"github.com/go-chi/chi/v5/middleware"
)

type capture struct {
	mu     sync.Mutex
	events []cgaudit.Event
}

func (c *capture) Publish(_ string, data []byte) error {
	var ev cgaudit.Event
	_ = json.Unmarshal(data, &ev)
	c.mu.Lock()
	c.events = append(c.events, ev)
	c.mu.Unlock()
	return nil
}

// emitted runs fn with c as the audit publisher and returns the events it emitted.
func emitted(t *testing.T, fn func()) []cgaudit.Event {
	t.Helper()
	c := &capture{}
	cgaudit.SetPublisher(c, "audit.test")
	fn()
	cgaudit.SetPublisher(nil, "") // publishes what is queued, then returns
	return c.events
}

func TestUserFromRequest_NoContext_Anonymous(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	if got := userFromRequest(req); got != "anonymous" {
		t.Errorf("got %q, want anonymous", got)
	}
}

func TestUserFromRequest_NilRequest_Anonymous(t *testing.T) {
	if got := userFromRequest(nil); got != "anonymous" {
		t.Errorf("got %q, want anonymous", got)
	}
}

// Note: testing the OAuth-injected sub path is covered by the
// internal/server middleware tests — the context key is unexported there
// and re-exposing it here would couple the audit wrapper to internal
// middleware details.

// An operation is audited with its outcome — success, rejected (4xx), failed (5xx or no
// answer) — its status and cause, the request ID, and the subscriber masked.
func TestRequest_Outcomes(t *testing.T) {
	req := httptest.NewRequest("PUT", "/nudm-uecm/v1/imsi-286010000000001/registrations/amf-3gpp-access", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.RequestIDKey, "req-1"))
	events := emitted(t, func() {
		Request(req, "3GppRegistration", "nudm-uecm", "imsi-286010000000001", 201, "")
		Request(req, "3GppRegistration", "nudm-uecm", "imsi-286010000000001", 404, "USER_NOT_FOUND")
		Request(req, "3GppRegistration", "nudm-uecm", "imsi-286010000000001", 504, "TARGET_NF_NOT_REACHABLE")
		Request(req, "3GppRegistration", "nudm-uecm", "", 0, "")
	})
	want := []struct {
		outcome string
		status  int
		cause   string
	}{{"success", 201, ""}, {"rejected", 404, "USER_NOT_FOUND"}, {"failed", 504, "TARGET_NF_NOT_REACHABLE"}, {"failed", 0, ""}}
	if len(events) != len(want) {
		t.Fatalf("%d events, want %d", len(events), len(want))
	}
	for i, w := range want {
		ev := events[i]
		if ev.Outcome != w.outcome || ev.Status != w.status || ev.Cause != w.cause || ev.RequestID != "req-1" ||
			ev.UserID != "anonymous" || ev.Action != "3GppRegistration" {
			t.Errorf("event %d: %+v, want %+v", i, ev, w)
		}
	}
	if strings.Contains(events[0].ResourceID, "286010000000001") || events[0].ResourceID == "" {
		t.Errorf("subscriber not masked: %q", events[0].ResourceID)
	}
}

// What OAuth turned away and what the gateway did for NATS applications are audited too.
func TestRefusedAndAction(t *testing.T) {
	req := httptest.NewRequest("GET", "/nudm-sdm/v2/x", nil)
	events := emitted(t, func() {
		Refused(req, "", "nudm-sdm", 401, "expired")
		Action(context.Background(), "MtForwardSm", "nsmsf-sms", "imsi-286010000000001", "https://smsf:443", Failed, "HTTP_503")
	})
	if len(events) != 2 {
		t.Fatalf("%d events", len(events))
	}
	if ev := events[0]; ev.UserID != "anonymous" || ev.Outcome != Rejected || ev.Status != 401 || ev.Cause != "expired" || ev.Resource != "nudm-sdm" {
		t.Errorf("refused: %+v", ev)
	}
	if ev := events[1]; ev.UserID != "nats" || ev.Outcome != Failed || ev.Target != "https://smsf:443" ||
		ev.Cause != "HTTP_503" || strings.Contains(ev.ResourceID, "286010000000001") {
		t.Errorf("action: %+v", ev)
	}
}

// The recorder keeps the status and an error's cause, never a success body.
func TestRecorder(t *testing.T) {
	w := httptest.NewRecorder()
	rec := NewRecorder(w)
	rec.WriteHeader(http.StatusNotFound)
	_, _ = rec.Write([]byte(`{"status":404,"cause":"USER_NOT_FOUND"}`))
	if rec.Status() != 404 || rec.Cause() != "USER_NOT_FOUND" || w.Code != 404 {
		t.Errorf("status %d cause %q", rec.Status(), rec.Cause())
	}

	ok := NewRecorder(httptest.NewRecorder())
	_, _ = ok.Write([]byte(`{"encPermanentKey":"SECRET"}`))
	if ok.Status() != 200 || len(ok.body) != 0 {
		t.Errorf("success: status %d, kept %q", ok.Status(), ok.body)
	}
}
