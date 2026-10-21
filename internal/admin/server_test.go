// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package admin_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/admin"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
)

type MockNatsClient struct {
	mock.Mock
}

func (m *MockNatsClient) Request(ctx context.Context, subject string, data []byte, timeout time.Duration) ([]byte, error) {
	return nil, nil
}
func (m *MockNatsClient) Publish(subject string, data []byte) error { return nil }
func (m *MockNatsClient) IsConnected() bool {
	args := m.Called()
	return args.Bool(0)
}
func (m *MockNatsClient) GetConn() *nats.Conn { return nil }
func (m *MockNatsClient) Close()              {}

func TestAdminServer_HealthLive(t *testing.T) {
	mockNats := new(MockNatsClient)
	srv := admin.NewAdminServer(mockNats)
	r := srv.SetupRouter()

	req := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminServer_HealthReady_Connected(t *testing.T) {
	mockNats := new(MockNatsClient)
	mockNats.On("IsConnected").Return(true)
	srv := admin.NewAdminServer(mockNats)
	r := srv.SetupRouter()

	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// An empty list, not null: a consumer can iterate it without a nil check.
	assert.JSONEq(t, `{"ready":true,"reasons":[]}`, w.Body.String())
}

func TestAdminServer_HealthReady_Disconnected(t *testing.T) {
	mockNats := new(MockNatsClient)
	mockNats.On("IsConnected").Return(false)
	srv := admin.NewAdminServer(mockNats)
	r := srv.SetupRouter()

	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// A draining gateway is not ready even though NATS is connected, and still alive.
func TestAdminServer_HealthReady_Draining(t *testing.T) {
	mockNats := new(MockNatsClient)
	mockNats.On("IsConnected").Return(true)
	srv := admin.NewAdminServer(mockNats)
	r := srv.SetupRouter()

	srv.Drain()

	for path, want := range map[string]int{
		"/health/ready": http.StatusServiceUnavailable,
		"/health/live":  http.StatusOK,
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		assert.Equal(t, want, w.Code, path)
	}
}

func TestAdminServer_Stats(t *testing.T) {
	mockNats := new(MockNatsClient)
	mockNats.On("IsConnected").Return(true)
	srv := admin.NewAdminServer(mockNats)
	r := srv.SetupRouter()

	req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var stats map[string]interface{}
	assert.NoError(t, json.NewDecoder(w.Body).Decode(&stats))
	assert.Equal(t, true, stats["nats_connected"])
}

// The health endpoints are open to anyone who reaches the admin port: a slow or idle
// client must not hold a connection open.
func TestHTTPServer_Timeouts(t *testing.T) {
	srv := admin.NewAdminServer(nil).HTTPServer(":0")
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatalf("timeouts unset: %+v", srv)
	}
}

// A readiness check added by the gateway, such as OAuth holding a verification key, makes
// /health/ready fail while it is false.
func TestAdminServer_HealthReady_Check(t *testing.T) {
	mockNats := new(MockNatsClient)
	mockNats.On("IsConnected").Return(true)
	srv := admin.NewAdminServer(mockNats)
	var ok bool
	srv.AddReadinessCheck("test_check", func() bool { return ok })
	r := srv.SetupRouter()

	for _, want := range []int{http.StatusServiceUnavailable, http.StatusOK} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
		assert.Equal(t, want, w.Code)
		ok = true
	}
}

// With a token, /metrics and /admin/* answer only requests carrying it; the health endpoints
// stay open for the kubelet.
func TestAdminServer_Token(t *testing.T) {
	mockNats := new(MockNatsClient)
	mockNats.On("IsConnected").Return(true)
	srv := admin.NewAdminServer(mockNats)
	srv.RequireToken(tokenFile(t, "s3cret"))
	r := srv.SetupRouter()

	for _, c := range []struct {
		path, authz string
		want        int
	}{
		{"/metrics", "", http.StatusUnauthorized},
		{"/metrics", "Bearer wrong", http.StatusUnauthorized},
		{"/metrics", "Basic s3cret", http.StatusUnauthorized},
		{"/metrics", "Bearer s3cret", http.StatusOK},
		{"/admin/stats", "", http.StatusUnauthorized},
		{"/admin/stats", "Bearer s3cret", http.StatusOK},
		{"/health/live", "", http.StatusOK},
		{"/health/ready", "", http.StatusOK},
	} {
		req := httptest.NewRequest(http.MethodGet, c.path, nil)
		if c.authz != "" {
			req.Header.Set("Authorization", c.authz)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, c.want, w.Code, "%s %q", c.path, c.authz)
	}
}

// A 503 says why, and readiness is logged when it changes, not at every probe.
func TestAdminServer_ReadyReasons(t *testing.T) {
	mockNats := new(MockNatsClient)
	mockNats.On("IsConnected").Return(false)
	var logs strings.Builder
	srv := admin.NewAdminServer(mockNats)
	srv.Log = slog.New(slog.NewTextHandler(&logs, nil))
	srv.AddReadinessCheck("oauth_no_verification_key", func() bool { return false })
	srv.Drain()
	r := srv.SetupRouter()

	for range 3 {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.JSONEq(t, `{"ready":false,"reasons":["draining","nats_disconnected","oauth_no_verification_key"]}`, w.Body.String())
	}
	assert.Equal(t, 1, strings.Count(logs.String(), "Not ready"), logs.String())
}

func tokenFile(t *testing.T, token string) *admin.TokenFile {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(path, []byte(token+"\n"), 0o600))
	tf, err := admin.NewTokenFile(path)
	require.NoError(t, err)
	return tf
}

// A rotated token takes effect without a restart: the file is read again after tokenReread.
// A file that cannot be read then leaves the last token in force.
func TestTokenFile_Rotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(path, []byte("old\n"), 0o600))
	tf, err := admin.NewTokenFile(path)
	require.NoError(t, err)
	now := time.Now()
	assert.Equal(t, "old", string(admin.TokenAt(tf, now)))

	require.NoError(t, os.WriteFile(path, []byte("new\n"), 0o600))
	assert.Equal(t, "old", string(admin.TokenAt(tf, now.Add(time.Second))), "read again before tokenReread")
	assert.Equal(t, "new", string(admin.TokenAt(tf, now.Add(11*time.Second))))

	require.NoError(t, os.Remove(path))
	assert.Equal(t, "new", string(admin.TokenAt(tf, now.Add(30*time.Second))), "the last token stays when the file is gone")

	_, err = admin.NewTokenFile(path)
	assert.Error(t, err, "a missing file at start")
}
