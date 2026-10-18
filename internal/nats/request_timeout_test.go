// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nats_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/nats"
	gnats "github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The timeout argument bounds the wait: an HTTP request's context has no deadline of its
// own. ctx here only keeps a broken Request from hanging the test.
func TestRequest_Timeout(t *testing.T) {
	s := runServer(nil)
	defer s.Shutdown()
	client, err := nats.NewClient(s.ClientURL(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	defer client.Close()

	_, err = client.GetConn().Subscribe("5g.silent", func(*gnats.Msg) {})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	_, err = client.Request(ctx, "5g.silent", []byte(`{}`), 100*time.Millisecond)
	elapsed := time.Since(start)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.GreaterOrEqual(t, elapsed, 100*time.Millisecond)
	assert.Less(t, elapsed, time.Second)

	_, err = client.Request(ctx, "5g.nobody", []byte(`{}`), time.Second)
	assert.ErrorIs(t, err, gnats.ErrNoResponders)
}
