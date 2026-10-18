// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package admin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/admin"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

// The admin port has no authentication: a slow or idle client must not hold a
// connection open.
func TestHTTPServer_Timeouts(t *testing.T) {
	srv := admin.NewAdminServer(nil).HTTPServer(":0")
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatalf("timeouts unset: %+v", srv)
	}
}
