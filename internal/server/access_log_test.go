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

	"github.com/go-chi/chi/v5"
)

const (
	testSUPI = "imsi-001010000000001"
	testGPSI = "msisdn-905551112233"
)

// accessRouter is the production middleware chain, logging at level into the returned
// buffer, with routes that answer 200, 504, nothing at all, and a panic.
func accessRouter(level slog.Level) (*chi.Mux, *bytes.Buffer) {
	var buf bytes.Buffer
	r := chi.NewRouter()
	RegisterMiddleware(r, slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: level})))
	r.Get("/nudm-sdm/v1/{supi}/am-data", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{}"))
	})
	r.Get("/nudm-sdm/v1/{supi}/sms-data", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGatewayTimeout)
	})
	r.Get("/nudm-sdm/v1/{supi}/silent", func(http.ResponseWriter, *http.Request) {})
	r.Get("/nudm-sdm/v1/{supi}/boom", func(http.ResponseWriter, *http.Request) { panic("boom") })
	return r, &buf
}

// lines decodes the JSON lines written to buf.
func lines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not a JSON line: %q", l)
		}
		out = append(out, m)
	}
	return out
}

// The access line names the route, never the URI: neither the SUPI in the path nor the
// GPSI in the query reaches the log, also for a path no route matches.
func TestAccessLog_NoSubscriberIdentifiers(t *testing.T) {
	r, buf := accessRouter(slog.LevelDebug)
	for path, route := range map[string]string{
		"/nudm-sdm/v1/" + testSUPI + "/am-data?gpsi=" + testGPSI: "/nudm-sdm/v1/{supi}/am-data",
		"/nudm-xyz/v1/" + testSUPI + "?gpsi=" + testGPSI:         unmatchedRoute,
	} {
		buf.Reset()
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))

		got := lines(t, buf)
		if len(got) != 1 {
			t.Fatalf("%s: %d lines, want 1: %s", path, len(got), buf)
		}
		if got[0]["route"] != route || got[0]["msg"] != "SBI request" || got[0]["request_id"] == "" {
			t.Errorf("%s: line %v, want route %q and a request id", path, got[0], route)
		}
		if strings.Contains(buf.String(), testSUPI) || strings.Contains(buf.String(), testGPSI) {
			t.Errorf("%s: subscriber identifier logged: %s", path, buf)
		}
	}
}

// One line per request is debugging; a 5xx, the recovered panic's included, is a warning,
// so LOG_LEVEL=info logs failures only.
func TestAccessLog_Levels(t *testing.T) {
	for _, tc := range []struct {
		resource string
		status   float64
		level    string // "" when nothing is logged at info
	}{
		{"am-data", 200, ""},
		{"silent", 200, ""},
		{"sms-data", 504, "WARN"},
		{"boom", 500, "WARN"},
	} {
		path := "/nudm-sdm/v1/" + testSUPI + "/" + tc.resource
		for _, level := range []slog.Level{slog.LevelDebug, slog.LevelInfo} {
			r, buf := accessRouter(level)
			r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))

			var access []map[string]any
			for _, l := range lines(t, buf) {
				if l["msg"] == "SBI request" {
					access = append(access, l)
				}
			}
			want := tc.level
			if want == "" && level == slog.LevelDebug {
				want = "DEBUG"
			}
			if want == "" {
				if len(access) != 0 {
					t.Errorf("%s at %s: logged %v, want nothing", tc.resource, level, access)
				}
				continue
			}
			if len(access) != 1 || access[0]["level"] != want || access[0]["status"] != tc.status {
				t.Errorf("%s at %s: %v, want one %s line with status %v", tc.resource, level, access, want, tc.status)
			}
		}
	}
}
