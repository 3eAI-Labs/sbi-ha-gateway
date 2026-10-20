// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	stdlog "log"
	"log/slog"
	"strings"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
)

// ErrorLog is an http.Server's ErrorLog for port (sbi, admin). A TLS handshake error is
// counted in tls_handshake_failures_total and logged at debug: scanners, and clients without
// the certificate the port asks for, make one per connection. Anything else is logged at warn.
func ErrorLog(log *slog.Logger, port string) *stdlog.Logger {
	return stdlog.New(errorLogWriter{log: log, port: port}, "", 0)
}

type errorLogWriter struct {
	log  *slog.Logger
	port string
}

func (w errorLogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	if strings.Contains(msg, "TLS handshake error") {
		metrics.RecordTLSHandshakeFailure(w.port)
		w.log.Debug(msg, slog.String("port", w.port))
		return len(p), nil
	}
	w.log.Warn(msg, slog.String("port", w.port))
	return len(p), nil
}
