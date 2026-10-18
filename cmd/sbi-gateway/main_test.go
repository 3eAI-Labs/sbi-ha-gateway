// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"net"
	"net/http"
	"strconv"
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
	t.Setenv("SHUTDOWN_DRAIN_DELAY", "0s")

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
		"unknown LOG_LEVEL":             {"LOG_LEVEL", "verbose"},
		"MAX_RETRIES 0":                 {"MAX_RETRIES", "0"},
		"negative RETRY_BASE_DELAY":     {"RETRY_BASE_DELAY", "-1s"},
		"negative SHUTDOWN_DRAIN_DELAY": {"SHUTDOWN_DRAIN_DELAY", "-1s"},
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

// After the signal the SBI port goes on answering for SHUTDOWN_DRAIN_DELAY while the
// readiness probe fails, so that connections still routed to a terminating pod are served;
// only then does the gateway stop listening.
func TestRunWithContext_DrainsBeforeClosing(t *testing.T) {
	s := runServer(nil)
	defer s.Shutdown()

	sbiPort, adminPort := freePort(t), freePort(t)
	t.Setenv("NATS_URL", s.ClientURL())
	t.Setenv("SBI_PORT", sbiPort)
	t.Setenv("ADMIN_PORT", adminPort)
	t.Setenv("SHUTDOWN_DRAIN_DELAY", "1s")
	ready := "http://127.0.0.1:" + adminPort + "/health/ready"
	sbi := "http://127.0.0.1:" + sbiPort + "/nudm-sdm/v1/imsi-001010000000001/am-data"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- RunWithContext(ctx) }()

	waitStatus(t, ready, http.StatusOK)
	cancel()
	signalled := time.Now()
	waitStatus(t, ready, http.StatusServiceUnavailable)

	// Any HTTP answer will do: no application is on NATS, so it is a 504.
	if _, err := get(sbi); err != nil {
		t.Fatalf("SBI port refused a request during the drain: %v", err)
	}

	select {
	case err := <-errCh:
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, time.Since(signalled), time.Second, "stopped before the drain delay")
	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown timeout")
	}
	if _, err := get(sbi); err == nil {
		t.Error("SBI port still answers after shutdown")
	}
}

// freePort returns a TCP port nothing listens on at the time of the call.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}

// get makes one request on a connection of its own.
func get(url string) (int, error) {
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := c.Get(url)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// waitStatus polls url until it answers want, for up to 5 seconds.
func waitStatus(t *testing.T, url string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, err := get(url)
		if err == nil && code == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: got %d (%v), want %d", url, code, err, want)
		}
		time.Sleep(20 * time.Millisecond)
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
