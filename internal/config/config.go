// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all application configuration
type Config struct {
	// Server Configuration
	SBIPort   string
	AdminPort string

	// TLS Configuration. When both fields are set the server uses TLS 1.3;
	// otherwise it falls back to h2c (cleartext HTTP/2) for internal mesh use.
	TLSCertFile string
	TLSKeyFile  string

	// mTLS — server-side peer cert verification per TS 33.310.
	//   MTLSClientCAFile   — PEM bundle of CAs trusted to sign peer certs.
	//   MTLSClientAuthMode — off / optional / require. Defaults to off so
	//                        the carrier-grade flip is explicit (operators
	//                        shouldn't accidentally enable mTLS by setting
	//                        the CA file).
	// Outbound (client-side) mTLS uses MTLSOutboundCertFile / KeyFile / CAFile;
	// gateway presents OutboundCert to peer NFs and verifies their certs
	// against OutboundCA. All three or none — partial config is fatal.
	MTLSClientCAFile     string
	MTLSClientAuthMode   string
	MTLSOutboundCertFile string
	MTLSOutboundKeyFile  string
	MTLSOutboundCAFile   string

	// NATS Configuration
	NatsURL            string
	NatsConnectTimeout time.Duration
	NatsRequestTimeout time.Duration

	// Logging
	LogLevel string

	// Retry Configuration
	MaxRetries     int
	RetryBaseDelay time.Duration

	// Rate Limiting (per NF Instance ID, falls back to remote IP)
	RateLimitRPS   float64
	RateLimitBurst int

	// OAuth2 NF token authentication per TS 33.501 §13.4.1.
	// Disabled by default — operators must opt in by setting OAUTH_AUDIENCE
	// and at least one JWKS source. OAUTH_DISABLED is a separate explicit
	// kill switch for development environments where setting up an NRF is
	// not worth the friction.
	OAuthDisabled           bool
	OAuthAudience           string        // expected `aud` claim — this NF's instance ID
	OAuthNRFJWKSURL         string        // NRF's JWKS endpoint
	OAuthJWKSFile           string        // static JWKS file (CI/airgap fallback)
	OAuthJWKSRefresh        time.Duration // JWKS refresh interval, default 5m
	OAuthClockSkew          time.Duration // ± exp/nbf tolerance, default 30s
	OAuthResultCacheTTL     time.Duration // per-token positive cache, default 60s
	OAuthRequireCertBinding bool          // RFC 8705 — reject tokens without cnf when true (default false)

	// Outbound delivery profile. "sbi_direct" routes via
	// HTTP/2 SBI to the URI in the notification payload (with HA failover
	// when alternateCallbackUris is present); "scef_rest" causes the
	// gateway to ack the NATS message and let an external SCEF adapter
	// deliver. Invalid values are fatal at startup.
	OutboundProfile string

	// SMS (OTA) surfaces: serving-SMSF lookup and Nsmsf SendSMS. Disabled by
	// default so existing deployments don't open the UECM/SMSF subjects
	// without operator opt-in.
	OTAEnabled      bool
	OTAResolverFile string        // optional MSISDN→{Supi,SmsfFqdn,SmsfPlmnId} JSON
	OTAUecmTimeout  time.Duration // probe budget for the UECM reply; default 3s (fail-fast for OTA Diameter fallback)

	// Audit of state-changing operations. The disable flag is the kill
	// switch for development; when audit is on, events go to the NATS
	// subject below (default "audit.events" matches the workspace
	// convention). Subject can be tenant-prefixed for multi-tenant clusters.
	AuditDisabled    bool
	AuditNATSSubject string
}

// TLSEnabled reports whether both certificate and key are configured.
func (c *Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

// Load reads configuration from environment variables with defaults
func Load() *Config {
	return &Config{
		// Server
		SBIPort:   getEnv("SBI_PORT", "8080"),
		AdminPort: getEnv("ADMIN_PORT", "9090"),

		// TLS (empty defaults → h2c)
		TLSCertFile: getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:  getEnv("TLS_KEY_FILE", ""),

		// mTLS (defaults: off until operator opts in)
		MTLSClientCAFile:     getEnv("MTLS_CLIENT_CA_FILE", ""),
		MTLSClientAuthMode:   getEnv("MTLS_CLIENT_AUTH_MODE", "off"),
		MTLSOutboundCertFile: getEnv("MTLS_OUTBOUND_CERT_FILE", ""),
		MTLSOutboundKeyFile:  getEnv("MTLS_OUTBOUND_KEY_FILE", ""),
		MTLSOutboundCAFile:   getEnv("MTLS_OUTBOUND_CA_FILE", ""),

		// NATS
		NatsURL:            getEnv("NATS_URL", "nats://localhost:4222"),
		NatsConnectTimeout: getDurationEnv("NATS_CONNECT_TIMEOUT", 5*time.Second),
		NatsRequestTimeout: getDurationEnv("NATS_REQUEST_TIMEOUT", 2*time.Second),

		// Logging
		LogLevel: getEnv("LOG_LEVEL", "info"),

		// Retry
		MaxRetries:     getIntEnv("MAX_RETRIES", 3),
		RetryBaseDelay: getDurationEnv("RETRY_BASE_DELAY", 1*time.Second),

		// Rate limiting (0 RPS disables it)
		RateLimitRPS:   getFloatEnv("RATE_LIMIT_RPS", 0),
		RateLimitBurst: getIntEnv("RATE_LIMIT_BURST", 100),

		// OAuth2 NF tokens (defaults: disabled until operator opts in).
		OAuthDisabled:           getBoolEnv("OAUTH_DISABLED", true),
		OAuthAudience:           getEnv("OAUTH_AUDIENCE", ""),
		OAuthNRFJWKSURL:         getEnv("OAUTH_NRF_JWKS_URL", ""),
		OAuthJWKSFile:           getEnv("OAUTH_JWKS_FILE", ""),
		OAuthJWKSRefresh:        getDurationEnv("OAUTH_JWKS_REFRESH", 5*time.Minute),
		OAuthClockSkew:          getDurationEnv("OAUTH_CLOCK_SKEW", 30*time.Second),
		OAuthResultCacheTTL:     getDurationEnv("OAUTH_RESULT_CACHE_TTL", 60*time.Second),
		OAuthRequireCertBinding: getBoolEnv("OAUTH_REQUIRE_CERT_BINDING", false),

		// Outbound profile (default: sbi_direct).
		OutboundProfile: getEnv("OUTBOUND_PROFILE", "sbi_direct"),

		// SMS (OTA) surfaces (default: off until operator opts in).
		OTAEnabled:      getBoolEnv("OTA_ENABLED", false),
		OTAResolverFile: getEnv("OTA_RESOLVER_FILE", ""),
		OTAUecmTimeout:  getDurationEnv("OTA_UECM_TIMEOUT", 3*time.Second),

		// Audit (default: enabled — slog fallback if NATS publisher absent).
		AuditDisabled:    getBoolEnv("AUDIT_DISABLED", false),
		AuditNATSSubject: getEnv("AUDIT_NATS_SUBJECT", "audit.events"),
	}
}

// getBoolEnv parses a boolean env var. "1", "true", "TRUE", "yes" are true;
// anything else (including empty) returns the default. Strict on purpose —
// silent acceptance of typos like "ture" is the kind of thing that turns
// off auth in production.
func getBoolEnv(key string, defaultVal bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	switch strings.ToLower(val) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return defaultVal
	}
}

// getEnv returns the value of an environment variable or a default value
func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// getIntEnv returns an integer environment variable or a default value
func getIntEnv(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}

// getFloatEnv returns a float environment variable or a default value
func getFloatEnv(key string, defaultVal float64) float64 {
	if val := os.Getenv(key); val != "" {
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			return f
		}
	}
	return defaultVal
}

// getDurationEnv returns a duration environment variable or a default value
func getDurationEnv(key string, defaultVal time.Duration) time.Duration {
	if val := os.Getenv(key); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return defaultVal
}
