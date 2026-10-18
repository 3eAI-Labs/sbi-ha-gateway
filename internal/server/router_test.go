// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package server_test

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/server"
	"github.com/stretchr/testify/assert"
)

func TestNewRouter(t *testing.T) {
	// Create a no-op logger for testing
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	timeout := 2 * time.Second

	cfg := server.RouterConfig{
		AuthHandler: handlers.NewAuthHandler(log, nil, timeout),
		MobH:        handlers.NewMobilityHandler(log, nil, timeout),
		DataH:       handlers.NewDataHandler(log, nil, timeout),
		MtH:         handlers.NewMTHandler(log, nil, timeout),
	}

	r := server.NewRouter(cfg)
	assert.NotNil(t, r)
}

func TestNewRouter_NilHandlers(t *testing.T) {
	// Test that router works with nil handlers
	cfg := server.RouterConfig{}

	r := server.NewRouter(cfg)
	assert.NotNil(t, r)
}
