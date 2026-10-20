// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
	dto "github.com/prometheus/client_model/go"
)

// A TLS handshake error is counted and logged at debug; any other server error at warn.
func TestErrorLog(t *testing.T) {
	var logs strings.Builder
	l := ErrorLog(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})), "sbi")
	read := func() float64 {
		var m dto.Metric
		_ = metrics.TLSHandshakeFailures.WithLabelValues("sbi").Write(&m)
		return m.GetCounter().GetValue()
	}
	before := read()
	l.Printf("http: TLS handshake error from 10.0.0.9:51234: tls: client didn't provide a certificate")
	l.Printf("http: Accept error: too many open files; retrying in 5ms")
	if got := read() - before; got != 1 {
		t.Errorf("%v handshake failures counted, want 1", got)
	}
	if !strings.Contains(logs.String(), "level=DEBUG msg=\"http: TLS handshake error") ||
		!strings.Contains(logs.String(), "level=WARN msg=\"http: Accept error") {
		t.Errorf("levels:\n%s", logs.String())
	}
}
