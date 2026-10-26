// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	sbiclient "github.com/3eAI-Labs/sbi-ha-gateway-client"
)

// Config holds all application configuration
type Config struct {
	// Server Configuration
	SBIPort   string
	AdminPort string
	// AdminTokenFile holds the bearer token /metrics and /admin/* require, unless
	// AdminAuthDisabled.
	AdminTokenFile    string
	AdminAuthDisabled bool
	// AdminTLS serves the admin port over TLS with the SBI port's certificate; false is an
	// explicit choice.
	AdminTLS bool

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
	// AllowPlaintextSBI lets the SBI port serve cleartext h2c without TLS_CERT_FILE and
	// TLS_KEY_FILE; without it the gateway refuses to start.
	AllowPlaintextSBI    bool
	MTLSClientCAFile     string
	MTLSClientAuthMode   string
	MTLSOutboundCertFile string
	MTLSOutboundKeyFile  string
	MTLSOutboundCAFile   string

	// NATS Configuration
	NatsURL            string
	NatsConnectTimeout time.Duration
	NatsRequestTimeout time.Duration
	// NATS authentication (at most one method; secrets as files) and TLS.
	NatsCredsFile    string
	NatsNkeySeedFile string
	NatsUser         string
	NatsPasswordFile string
	NatsTokenFile    string
	NatsTLSCAFile    string
	NatsTLSCertFile  string
	NatsTLSKeyFile   string

	// Logging
	LogLevel string

	// Retry Configuration
	MaxRetries     int
	RetryBaseDelay time.Duration
	// NotifyWorkers is how many notifications are delivered at once.
	NotifyWorkers int

	// ShutdownDrainDelay is how long the SBI port keeps serving after SIGTERM, answering not
	// ready meanwhile, before it stops accepting connections.
	ShutdownDrainDelay time.Duration
	// ShutdownTimeout bounds what follows the drain delay: requests in flight, notification
	// deliveries and SMS being sent finish within it, side by side.
	ShutdownTimeout time.Duration

	// Rate Limiting (per NF Instance ID, falls back to remote IP)
	RateLimitRPS   float64
	RateLimitBurst int

	// OAuth2 NF token authentication per TS 33.501 §13.4.1.
	// Disabled by default — operators must opt in by setting OAUTH_AUDIENCE
	// and at least one JWKS source. OAUTH_DISABLED is a separate explicit
	// kill switch for development environments where setting up an NRF is
	// not worth the friction.
	OAuthDisabled           bool
	OAuthAudience           string        // expected `aud` claim — this NF's instance ID(s), comma-separated
	OAuthNRFJWKSURL         string        // NRF's JWKS endpoint
	OAuthJWKSFile           string        // static JWKS file (CI/airgap fallback)
	OAuthJWKSRefresh        time.Duration // JWKS refresh interval, default 5m
	OAuthClockSkew          time.Duration // ± exp/nbf tolerance, default 30s
	OAuthResultCacheTTL     time.Duration // per-token positive cache, default 60s
	OAuthRequireCertBinding bool          // RFC 8705 — reject tokens without cnf when true (default false)

	// Registration with the NRF (TS 29.510 Nnrf_NFManagement). NRFAPIRoot and NRFProfilesFile
	// together, or neither: without them the gateway does not register. NRFHeartbeatTimer is
	// the heartbeat interval proposed at registration (whole seconds); 0 leaves it to the NRF.
	NRFAPIRoot        string
	NRFProfilesFile   string
	NRFHeartbeatTimer time.Duration
	// NRFNotificationAPIRoot is the {apiRoot} the NRF reaches the SBI port at: the gateway
	// subscribes to the SMSFs it discovers, with callback URIs under it. Empty: no
	// subscription; a discovered SMSF serves for the validityPeriod alone.
	NRFNotificationAPIRoot string

	// Outbound delivery profile. "sbi_direct" routes via
	// HTTP/2 SBI to the URI in the notification payload (with HA failover
	// when alternateCallbackUris is present); "scef_rest" causes the
	// gateway to ack the NATS message and let an external SCEF adapter
	// deliver. Invalid values are fatal at startup.
	// OutboundAllowedDestinations lists the hosts callbacks and SMSF calls may reach (host
	// names, ".domain" suffixes, CIDRs, addresses); empty: none, unless OutboundAllowAny.
	OutboundAllowedDestinations string
	OutboundAllowAny            bool
	OutboundProfile             string

	// SMS surfaces: serving-SMSF lookup and Nsmsf MtForwardSm. Off by default, so that a
	// deployment does not consume the UECM and SMSF subjects without the operator opting in.
	// SMSStream is the JetStream stream that captures the SMS to send (created, with one
	// replica, when it does not exist); SMSDeliveryEventSubject where each SMS's result goes.
	SMSEnabled              bool
	SMSResolverFile         string        // optional MSISDN→{Supi,SmsfFqdn,SmsfInstanceId,SmsfPlmnId} JSON
	SMSUecmTimeout          time.Duration // budget for the UECM reply; default 3s: a lookup is a probe, fail fast
	SMSStream               string
	SMSDeliveryEventSubject string

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

// Load reads configuration from environment variables with defaults. A value that does not
// parse is an error, never its default: OAUTH_DISABLED=fasle leaving OAuth off, or
// RATE_LIMIT_RPS=100/s switching the limiter off, is what this prevents. All such values
// are reported at once.
func Load() (*Config, error) {
	var l loader
	cfg := &Config{
		// Server
		SBIPort:           l.str("SBI_PORT", "8080"),
		AdminPort:         l.str("ADMIN_PORT", "9090"),
		AdminTokenFile:    l.str("ADMIN_TOKEN_FILE", ""),
		AdminAuthDisabled: l.boolean("ADMIN_AUTH_DISABLED", false),
		AdminTLS:          l.boolean("ADMIN_TLS", true),

		// TLS (empty defaults → h2c)
		TLSCertFile: l.str("TLS_CERT_FILE", ""),
		TLSKeyFile:  l.str("TLS_KEY_FILE", ""),

		// Secure by default: TLS, client certificates and OAuth are
		// required; each is switched off only by its own explicit setting.
		AllowPlaintextSBI:    l.boolean("ALLOW_PLAINTEXT_SBI", false),
		MTLSClientCAFile:     l.str("MTLS_CLIENT_CA_FILE", ""),
		MTLSClientAuthMode:   l.str("MTLS_CLIENT_AUTH_MODE", "require"),
		MTLSOutboundCertFile: l.str("MTLS_OUTBOUND_CERT_FILE", ""),
		MTLSOutboundKeyFile:  l.str("MTLS_OUTBOUND_KEY_FILE", ""),
		MTLSOutboundCAFile:   l.str("MTLS_OUTBOUND_CA_FILE", ""),

		// NATS
		NatsURL:            l.str("NATS_URL", "nats://localhost:4222"),
		NatsConnectTimeout: l.duration("NATS_CONNECT_TIMEOUT", 5*time.Second),
		NatsRequestTimeout: l.duration("NATS_REQUEST_TIMEOUT", 2*time.Second),
		NatsCredsFile:      l.str("NATS_CREDS_FILE", ""),
		NatsNkeySeedFile:   l.str("NATS_NKEY_SEED_FILE", ""),
		NatsUser:           l.str("NATS_USER", ""),
		NatsPasswordFile:   l.str("NATS_PASSWORD_FILE", ""),
		NatsTokenFile:      l.str("NATS_TOKEN_FILE", ""),
		NatsTLSCAFile:      l.str("NATS_TLS_CA_FILE", ""),
		NatsTLSCertFile:    l.str("NATS_TLS_CERT_FILE", ""),
		NatsTLSKeyFile:     l.str("NATS_TLS_KEY_FILE", ""),

		// Logging
		LogLevel: l.str("LOG_LEVEL", "info"),

		// Retry
		MaxRetries:     l.integer("MAX_RETRIES", 3),
		RetryBaseDelay: l.duration("RETRY_BASE_DELAY", 1*time.Second),
		NotifyWorkers:  l.integer("NOTIFY_WORKERS", 32),

		// Shutdown
		ShutdownDrainDelay: l.duration("SHUTDOWN_DRAIN_DELAY", 5*time.Second),
		ShutdownTimeout:    l.duration("SHUTDOWN_TIMEOUT", 20*time.Second),

		// Rate limiting (0 RPS disables it)
		RateLimitRPS:   l.float("RATE_LIMIT_RPS", 0),
		RateLimitBurst: l.integer("RATE_LIMIT_BURST", 100),

		// OAuth2 NF tokens: required unless OAUTH_DISABLED=true.
		OAuthDisabled:           l.boolean("OAUTH_DISABLED", false),
		OAuthAudience:           l.str("OAUTH_AUDIENCE", ""),
		OAuthNRFJWKSURL:         l.str("OAUTH_NRF_JWKS_URL", ""),
		OAuthJWKSFile:           l.str("OAUTH_JWKS_FILE", ""),
		OAuthJWKSRefresh:        l.duration("OAUTH_JWKS_REFRESH", 5*time.Minute),
		OAuthClockSkew:          l.duration("OAUTH_CLOCK_SKEW", 30*time.Second),
		OAuthResultCacheTTL:     l.duration("OAUTH_RESULT_CACHE_TTL", 60*time.Second),
		OAuthRequireCertBinding: l.boolean("OAUTH_REQUIRE_CERT_BINDING", false),

		// NRF registration (default: none).
		NRFAPIRoot:             l.str("NRF_API_ROOT", ""),
		NRFProfilesFile:        l.str("NRF_PROFILES_FILE", ""),
		NRFHeartbeatTimer:      l.duration("NRF_HEARTBEAT_TIMER", 0),
		NRFNotificationAPIRoot: l.str("NRF_NOTIFICATION_API_ROOT", ""),

		// Outbound profile (default: sbi_direct).
		OutboundProfile:             l.str("OUTBOUND_PROFILE", "sbi_direct"),
		OutboundAllowedDestinations: l.str("OUTBOUND_ALLOWED_DESTINATIONS", ""),
		OutboundAllowAny:            l.boolean("OUTBOUND_ALLOW_ANY", false),

		// SMS surfaces (default: off until the operator opts in).
		SMSEnabled:              l.boolean("SMS_ENABLED", false),
		SMSResolverFile:         l.str("SMS_RESOLVER_FILE", ""),
		SMSUecmTimeout:          l.duration("SMS_UECM_TIMEOUT", 3*time.Second),
		SMSStream:               l.name("SMS_STREAM", sbiclient.StreamSmsfSend, streamName, "a JetStream stream name"),
		SMSDeliveryEventSubject: l.name("SMS_DELIVERY_EVENT_SUBJECT", sbiclient.SubjectDeliveryEvent, subjectName, "a NATS subject without wildcards"),

		// Audit (default: enabled — slog fallback if NATS publisher absent).
		AuditDisabled:    l.boolean("AUDIT_DISABLED", false),
		AuditNATSSubject: l.str("AUDIT_NATS_SUBJECT", "audit.events"),
	}
	// Renamed in 0.5.0: an installation still setting the old names would lose its SMS
	// surfaces without a word.
	for old, now := range map[string]string{
		"OTA_ENABLED": "SMS_ENABLED", "OTA_RESOLVER_FILE": "SMS_RESOLVER_FILE", "OTA_UECM_TIMEOUT": "SMS_UECM_TIMEOUT",
	} {
		if os.Getenv(old) != "" {
			l.errs = append(l.errs, fmt.Errorf("%s was renamed %s", old, now))
		}
	}
	return cfg, errors.Join(l.errs...)
}

var (
	// streamName: a JetStream stream name has no whitespace, ".", "*", ">", "/" or "\".
	streamName = regexp.MustCompile(`^[^\s.*>/\\]{1,255}$`)
	// subjectName: dot-separated tokens, no wildcard.
	subjectName = regexp.MustCompile(`^[^\s.*>]+(\.[^\s.*>]+)*$`)
)

// name returns the variable, or def when it is empty; a value the pattern does not match is
// an error.
func (l *loader) name(key, def string, pattern *regexp.Regexp, want string) string {
	val := l.str(key, def)
	if !pattern.MatchString(val) {
		l.invalid(key, val, want)
	}
	return val
}

// loader reads environment variables and records each value that does not parse.
type loader struct{ errs []error }

func (l *loader) invalid(key, val, want string) {
	l.errs = append(l.errs, fmt.Errorf("%s=%q: want %s", key, val, want))
}

// str returns the variable, or def when it is empty.
func (l *loader) str(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}

// boolean accepts 1/0, true/false, yes/no and on/off in any case.
func (l *loader) boolean(key string, def bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	switch strings.ToLower(val) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	l.invalid(key, val, "true or false")
	return def
}

func (l *loader) integer(key string, def int) int {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		l.invalid(key, val, "an integer")
		return def
	}
	return i
}

func (l *loader) float(key string, def float64) float64 {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	f, err := strconv.ParseFloat(val, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		l.invalid(key, val, "a number")
		return def
	}
	return f
}

// duration takes a Go duration: "500ms", "2s", "5m".
func (l *loader) duration(key string, def time.Duration) time.Duration {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		l.invalid(key, val, `a duration such as "2s"`)
		return def
	}
	return d
}
