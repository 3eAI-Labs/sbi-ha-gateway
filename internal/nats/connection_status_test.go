// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nats_test

import (
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/nats"
	natsserver "github.com/nats-io/nats-server/v2/server"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The gateway starts while NATS is unreachable and keeps reconnecting; the connection
// gauge must be 0 until the first connection, then 1.
func TestConnectionGauge_StartsDisconnected(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())

	client, err := nats.NewClientWithTimeout("nats://127.0.0.1:"+strconv.Itoa(port), slog.New(slog.NewTextHandler(io.Discard, nil)), 200*time.Millisecond)
	require.NoError(t, err)
	defer client.Close()
	assert.False(t, client.IsConnected())
	assert.Equal(t, 0.0, connectionGauge(t))

	s := runServer(&natsserver.Options{Host: "127.0.0.1", Port: port})
	defer s.Shutdown()
	assert.Eventually(t, client.IsConnected, 10*time.Second, 50*time.Millisecond, "connection")
	assert.Eventually(t, func() bool { return connectionGauge(t) == 1 },
		10*time.Second, 50*time.Millisecond)
}

func connectionGauge(t *testing.T) float64 {
	var m dto.Metric
	require.NoError(t, metrics.NatsConnectionStatus.Write(&m))
	return m.GetGauge().GetValue()
}
