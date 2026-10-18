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
	for _, k := range strings.Fields(`ADMIN_PORT AUDIT_DISABLED AUDIT_NATS_SUBJECT LOG_LEVEL MAX_RETRIES
		MTLS_CLIENT_AUTH_MODE MTLS_CLIENT_CA_FILE MTLS_OUTBOUND_CA_FILE MTLS_OUTBOUND_CERT_FILE
		MTLS_OUTBOUND_KEY_FILE NATS_CONNECT_TIMEOUT NATS_REQUEST_TIMEOUT NATS_URL OAUTH_AUDIENCE
		OAUTH_CLOCK_SKEW OAUTH_DISABLED OAUTH_JWKS_FILE OAUTH_JWKS_REFRESH OAUTH_NRF_JWKS_URL
		OAUTH_REQUIRE_CERT_BINDING OAUTH_RESULT_CACHE_TTL OTA_ENABLED OTA_RESOLVER_FILE
		OTA_UECM_TIMEOUT OUTBOUND_PROFILE RATE_LIMIT_BURST RATE_LIMIT_RPS RETRY_BASE_DELAY
		SBI_PORT TLS_CERT_FILE TLS_KEY_FILE`) {
		t.Setenv(k, "")
	}
}

func TestLoad_Defaults(t *testing.T) {
	unsetConfigEnv(t)

	cfg := Load()

	assert.Equal(t, "8080", cfg.SBIPort)
	assert.Equal(t, "9090", cfg.AdminPort)
	assert.Equal(t, "nats://localhost:4222", cfg.NatsURL)
	assert.Equal(t, 5*time.Second, cfg.NatsConnectTimeout)
	assert.Equal(t, 2*time.Second, cfg.NatsRequestTimeout)
	assert.Equal(t, "info", cfg.LogLevel)
	assert.Equal(t, 3, cfg.MaxRetries)
	assert.Equal(t, 1*time.Second, cfg.RetryBaseDelay)
}

func TestLoad_FromEnv(t *testing.T) {
	t.Setenv("SBI_PORT", "9000")
	t.Setenv("ADMIN_PORT", "9091")
	t.Setenv("NATS_URL", "nats://custom:4222")
	t.Setenv("NATS_REQUEST_TIMEOUT", "5s")
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("MAX_RETRIES", "5")

	cfg := Load()

	assert.Equal(t, "9000", cfg.SBIPort)
	assert.Equal(t, "9091", cfg.AdminPort)
	assert.Equal(t, "nats://custom:4222", cfg.NatsURL)
	assert.Equal(t, 5*time.Second, cfg.NatsRequestTimeout)
	assert.Equal(t, "debug", cfg.LogLevel)
	assert.Equal(t, 5, cfg.MaxRetries)
}

func TestGetIntEnv_InvalidValue(t *testing.T) {
	t.Setenv("MAX_RETRIES", "invalid")

	val := getIntEnv("MAX_RETRIES", 3)
	assert.Equal(t, 3, val) // Should return default
}

func TestGetDurationEnv_InvalidValue(t *testing.T) {
	t.Setenv("NATS_REQUEST_TIMEOUT", "invalid")

	val := getDurationEnv("NATS_REQUEST_TIMEOUT", 2*time.Second)
	assert.Equal(t, 2*time.Second, val) // Should return default
}
