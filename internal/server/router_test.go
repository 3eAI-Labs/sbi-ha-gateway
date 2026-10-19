// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/server"
	gnats "github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
)

// app answers every operation with reply.
type app struct{ reply string }

func (a app) Request(context.Context, string, []byte, time.Duration) ([]byte, error) {
	return []byte(a.reply), nil
}
func (app) Publish(string, []byte) error { return nil }
func (app) IsConnected() bool            { return true }
func (app) GetConn() *gnats.Conn         { return nil }
func (app) Close()                       {}

// Through the whole middleware chain, an operation's access line and metric label are the
// specification's route, not the request URI with its SUPI.
func TestNewRouter_RouteInAccessLog(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r := server.NewRouter(server.RouterConfig{
		SBI:    handlers.NewSBIHandler(slog.New(slog.NewTextHandler(io.Discard, nil)), app{`{"body":{}}`}, time.Second),
		Logger: log,
	})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nudm-sdm/v2/imsi-001010000000001/am-data", nil))
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var line map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "SBI request" {
			line = m
		}
	}
	assert.Equal(t, "/nudm-sdm/v2/{supi}/am-data", line["route"])
	assert.NotContains(t, buf.String(), "imsi-001010000000001")
}

func TestNewRouter_NilHandlers(t *testing.T) {
	r := server.NewRouter(server.RouterConfig{})
	assert.NotNil(t, r)
}
