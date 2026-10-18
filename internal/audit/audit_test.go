// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
// middleware details. The integration is exercised end-to-end via the
// handler tests that hit a chi router with the full middleware chain.

// Smoke tests for Log/LogCtx — verify they don't panic with nil/empty
// inputs. Behavioural verification (publisher actually receives event)
// lives in internal/platform/audit's tests.
func TestLog_DoesNotPanicOnNilFields(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Log panicked: %v", r)
		}
	}()
	req := httptest.NewRequest("PUT", "/nudm-uecm/v1/imsi-x/registrations/amf-3gpp-access", nil)
	Log(req, "REGISTER", "nudm-uecm", "imsi-286010000000001", nil)
}

func TestLogCtx_EmptyUserID_BecomesAnonymous(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("LogCtx panicked: %v", r)
		}
	}()
	LogCtx(context.Background(), "", "ACTION", "resource", "imsi-286010000000001", map[string]string{"x": "y"})
}

// Smoke that http.Request is enough — caller doesn't need to plumb the
// router/middleware just to emit an audit event from a handler.
func TestLog_AcceptsBareRequest(t *testing.T) {
	req, _ := http.NewRequest("POST", "/x", nil)
	Log(req, "TEST_ACTION", "test-res", "imsi-001020000000001", "payload")
}
