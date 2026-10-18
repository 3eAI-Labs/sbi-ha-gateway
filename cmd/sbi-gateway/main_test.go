// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/stretchr/testify/assert"
)

func runServer(opts *natsserver.Options) *natsserver.Server {
	if opts == nil {
		opts = &natsserver.Options{
			Host: "127.0.0.1",
			Port: -1,
		}
	}
	s, err := natsserver.NewServer(opts)
	if err != nil {
		panic(err)
	}
	go s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		panic("not ready for connections")
	}
	return s
}

func TestRunWithContext(t *testing.T) {
	s := runServer(nil)
	defer s.Shutdown()

	t.Setenv("NATS_URL", s.ClientURL())
	t.Setenv("SBI_PORT", "0")
	t.Setenv("ADMIN_PORT", "0")

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunWithContext(ctx)
	}()

	// Wait for servers to start
	time.Sleep(100 * time.Millisecond)

	// Trigger shutdown via context cancellation
	cancel()

	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown timeout")
	}
}

func TestRunWithContext_NatsFailure(t *testing.T) {
	t.Setenv("NATS_URL", " %")

	ctx := context.Background()
	err := RunWithContext(ctx)
	assert.Error(t, err)
}

// Settings that would make the gateway run differently from what the operator asked
// stop it at start-up.
func TestRunWithContext_RejectsInvalidSettings(t *testing.T) {
	for name, env := range map[string][2]string{
		"unknown LOG_LEVEL":         {"LOG_LEVEL", "verbose"},
		"MAX_RETRIES 0":             {"MAX_RETRIES", "0"},
		"negative RETRY_BASE_DELAY": {"RETRY_BASE_DELAY", "-1s"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(env[0], env[1])
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := RunWithContext(ctx)
			if err == nil || !strings.Contains(err.Error(), env[0]) {
				t.Fatalf("got %v, want an error naming %s", err, env[0])
			}
		})
	}
}

func TestSBIServer_Timeouts(t *testing.T) {
	srv := sbiServer(":0", 2*time.Second, false)
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatalf("read/idle timeouts unset: %+v", srv)
	}
	if srv.WriteTimeout != 30*time.Second {
		t.Errorf("WriteTimeout = %s, want 30s", srv.WriteTimeout)
	}
	// The write timeout must outlast the wait for the application's reply.
	if got := sbiServer(":0", 45*time.Second, false).WriteTimeout; got != 55*time.Second {
		t.Errorf("WriteTimeout with a 45s NATS timeout = %s, want 55s", got)
	}
}

// HTTP/2 over TLS with TLS, h2c without; never cleartext HTTP/2 on a TLS port.
func TestSBIServer_Protocols(t *testing.T) {
	if p := sbiServer(":0", 0, true).Protocols; !p.HTTP2() || p.UnencryptedHTTP2() || !p.HTTP1() {
		t.Errorf("TLS: %s, want HTTP1 and HTTP2", p)
	}
	if p := sbiServer(":0", 0, false).Protocols; p.HTTP2() || !p.UnencryptedHTTP2() || !p.HTTP1() {
		t.Errorf("cleartext: %s, want HTTP1 and UnencryptedHTTP2", p)
	}
}
