// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// unsetConfigEnv empties every variable Load reads, for this test only; an empty value
// means the default.
func unsetConfigEnv(t *testing.T) {
	t.Helper()
	for _, k := range strings.Fields(`ADMIN_PORT AUDIT_DISABLED AUDIT_NATS_SUBJECT LOG_LEVEL MAX_RETRIES NOTIFY_WORKERS SHUTDOWN_TIMEOUT
		MTLS_CLIENT_AUTH_MODE MTLS_CLIENT_CA_FILE MTLS_OUTBOUND_CA_FILE MTLS_OUTBOUND_CERT_FILE
		MTLS_OUTBOUND_KEY_FILE NATS_CONNECT_TIMEOUT NATS_REQUEST_TIMEOUT NATS_URL NATS_CREDS_FILE
		NATS_NKEY_SEED_FILE NATS_USER NATS_PASSWORD_FILE NATS_TOKEN_FILE NATS_TLS_CA_FILE
		NATS_TLS_CERT_FILE NATS_TLS_KEY_FILE OAUTH_AUDIENCE
		OAUTH_CLOCK_SKEW OAUTH_DISABLED OAUTH_JWKS_FILE OAUTH_JWKS_REFRESH OAUTH_NRF_JWKS_URL
		OAUTH_REQUIRE_CERT_BINDING OAUTH_RESULT_CACHE_TTL OTA_ENABLED OTA_RESOLVER_FILE
		OTA_UECM_TIMEOUT OUTBOUND_PROFILE OUTBOUND_ALLOWED_DESTINATIONS OUTBOUND_ALLOW_ANY RATE_LIMIT_BURST RATE_LIMIT_RPS RETRY_BASE_DELAY
		SBI_PORT SHUTDOWN_DRAIN_DELAY TLS_CERT_FILE TLS_KEY_FILE ALLOW_PLAINTEXT_SBI`) {
		t.Setenv(k, "")
	}
}

func TestLoad_Defaults(t *testing.T) {
	unsetConfigEnv(t)

	cfg, err := Load()
	assert.NoError(t, err)

	assert.Equal(t, "8080", cfg.SBIPort)
	assert.Equal(t, "9090", cfg.AdminPort)
	assert.Equal(t, "nats://localhost:4222", cfg.NatsURL)
	assert.Equal(t, 5*time.Second, cfg.NatsConnectTimeout)
	assert.Equal(t, 2*time.Second, cfg.NatsRequestTimeout)
	assert.Equal(t, "info", cfg.LogLevel)
	assert.Equal(t, 3, cfg.MaxRetries)
	assert.Equal(t, 32, cfg.NotifyWorkers)
	assert.Equal(t, 20*time.Second, cfg.ShutdownTimeout)
	assert.Equal(t, 1*time.Second, cfg.RetryBaseDelay)
	assert.Equal(t, 5*time.Second, cfg.ShutdownDrainDelay)
	// Secure by default.
	assert.False(t, cfg.AllowPlaintextSBI)
	assert.Equal(t, "require", cfg.MTLSClientAuthMode)
	assert.False(t, cfg.OAuthDisabled)
}

func TestLoad_FromEnv(t *testing.T) {
	t.Setenv("SBI_PORT", "9000")
	t.Setenv("ADMIN_PORT", "9091")
	t.Setenv("NATS_URL", "nats://custom:4222")
	t.Setenv("NATS_REQUEST_TIMEOUT", "5s")
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("MAX_RETRIES", "5")
	t.Setenv("SHUTDOWN_DRAIN_DELAY", "0s")

	cfg, err := Load()
	assert.NoError(t, err)

	assert.Equal(t, "9000", cfg.SBIPort)
	assert.Equal(t, "9091", cfg.AdminPort)
	assert.Equal(t, "nats://custom:4222", cfg.NatsURL)
	assert.Equal(t, 5*time.Second, cfg.NatsRequestTimeout)
	assert.Equal(t, "debug", cfg.LogLevel)
	assert.Equal(t, 5, cfg.MaxRetries)
	assert.Equal(t, time.Duration(0), cfg.ShutdownDrainDelay)
}

// A value that does not parse stops the gateway, naming the variable, rather than taking
// the default: OAUTH_DISABLED=fasle would leave OAuth off, RATE_LIMIT_RPS=100/s the limiter.
func TestLoad_InvalidValues(t *testing.T) {
	for key, val := range map[string]string{
		"OAUTH_DISABLED":       "fasle",
		"OTA_ENABLED":          "ture",
		"RATE_LIMIT_RPS":       "100/s",
		"RATE_LIMIT_BURST":     "lots",
		"MAX_RETRIES":          "3x",
		"NATS_REQUEST_TIMEOUT": "2",
		"SHUTDOWN_DRAIN_DELAY": "five seconds",
	} {
		t.Run(key, func(t *testing.T) {
			unsetConfigEnv(t)
			t.Setenv(key, val)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), key) {
				t.Errorf("%s=%q: got %v, want an error naming %s", key, val, err, key)
			}
		})
	}
	unsetConfigEnv(t)
	t.Setenv("RATE_LIMIT_RPS", "NaN")
	if _, err := Load(); err == nil {
		t.Error("RATE_LIMIT_RPS=NaN accepted")
	}
}

// Every invalid value is reported at once.
func TestLoad_ReportsAllInvalidValues(t *testing.T) {
	unsetConfigEnv(t)
	t.Setenv("MAX_RETRIES", "x")
	t.Setenv("OAUTH_CLOCK_SKEW", "y")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "MAX_RETRIES") || !strings.Contains(err.Error(), "OAUTH_CLOCK_SKEW") {
		t.Errorf("got %v, want both variables named", err)
	}
}
