// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// RequestsTotal counts total HTTP requests by method, path, and status
	RequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbi_gateway",
			Name:      "requests_total",
			Help:      "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	// RequestDuration measures request latency in seconds
	RequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "sbi_gateway",
			Name:      "request_duration_seconds",
			Help:      "HTTP request latency in seconds",
			Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		},
		[]string{"method", "path"},
	)

	// NatsRequestsTotal counts NATS request/reply operations
	NatsRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbi_gateway",
			Name:      "nats_requests_total",
			Help:      "Total NATS request/reply operations by status: success, timeout, no_responders, error (no reply for another reason), jetstream_reply (a stream captured the request subject)",
		},
		[]string{"subject", "status"},
	)

	// NatsRequestDuration measures NATS request latency
	NatsRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "sbi_gateway",
			Name:      "nats_request_duration_seconds",
			Help:      "NATS request latency in seconds",
			Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2},
		},
		[]string{"subject"},
	)

	// SecurityProtection is 1 for each protection of the SBI port that is on, 0 for one an
	// explicit setting switched off: tls, client_certificate, oauth. Alert on 0 in production.
	SecurityProtection = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "sbi_gateway",
			Name:      "security_protection",
			Help:      "1 when the SBI protection is on, 0 when an explicit setting switched it off",
		},
		[]string{"protection"},
	)

	// NatsConnectionStatus indicates NATS connection state (1=connected, 0=disconnected)
	NatsConnectionStatus = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "sbi_gateway",
			Name:      "nats_connection_status",
			Help:      "NATS connection status (1=connected, 0=disconnected)",
		},
	)

	// ActiveRequests tracks in-flight requests
	ActiveRequests = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "sbi_gateway",
			Name:      "active_requests",
			Help:      "Number of currently active HTTP requests",
		},
	)

	// CallbackRetries counts callback delivery retries
	CallbackRetries = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbi_gateway",
			Name:      "callback_retries_total",
			Help:      "Total callback delivery retry attempts",
		},
		[]string{"status"},
	)

	// ErrorsTotal counts errors by type
	ErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbi_gateway",
			Name:      "errors_total",
			Help:      "Total errors by type",
		},
		[]string{"type", "cause"},
	)

	// OAuthValidations counts OAuth2 NF token validation outcomes. The
	// `reason` label uses oauth.FailReason values so dashboards can
	// distinguish "expired" from "wrong_audience" without parsing logs.
	OAuthValidations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbi_gateway",
			Name:      "oauth_validations_total",
			Help:      "OAuth2 NF token validation outcomes (TS 33.501 §13.4.1)",
		},
		[]string{"result", "reason"},
	)

	// OutboundDeliveries counts outbound notification delivery outcomes per
	// profile. The `result` label is bounded to a small enum so cardinality
	// stays predictable: ok | failover | bypassed | exhausted | client_error |
	// not_allowed | not_implemented.
	// OAuthJWKSRefreshes counts fetches of the NRF's JWKS: result ok or error.
	OAuthJWKSRefreshes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbi_gateway",
			Name:      "oauth_jwks_refreshes_total",
			Help:      "Fetches of the NRF's JWKS by result",
		},
		[]string{"result"},
	)

	// OAuthJWKSKeys is the number of verification keys (RS256/ES256) the gateway holds: 0
	// means every token is rejected.
	OAuthJWKSKeys = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "sbi_gateway",
		Name:      "oauth_jwks_keys",
		Help:      "Verification keys held; 0 rejects every token",
	})

	// OAuthJWKSLastRefresh is the time of the last successful JWKS fetch.
	OAuthJWKSLastRefresh = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "sbi_gateway",
		Name:      "oauth_jwks_last_refresh_timestamp_seconds",
		Help:      "Unix time of the last successful fetch of the NRF's JWKS",
	})

	// OutboundEndpointSkips counts callback URIs not called: reason "resting" (its network
	// function failed repeatedly and another endpoint was available) or "retry_after".
	OutboundEndpointSkips = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbi_gateway",
			Name:      "outbound_endpoint_skips_total",
			Help:      "Callback URIs not called because their network function rests or asked to wait (Retry-After)",
		},
		[]string{"reason"},
	)

	OutboundDeliveries = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbi_gateway",
			Name:      "outbound_deliveries_total",
			Help:      "Outbound notification delivery outcomes by profile (HA failover loop)",
		},
		[]string{"profile", "result"},
	)

	// OutboundEndpointPosition records which endpoint position succeeded
	// (0 = primary, 1 = first alternate, ...). A spike at >0 means the
	// primary is unhealthy — operator action signal without per-URL labels.
	OutboundEndpointPosition = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "sbi_gateway",
			Name:      "outbound_endpoint_position",
			Help:      "Position of the endpoint that successfully delivered (0=primary)",
			Buckets:   []float64{0, 1, 2, 3, 5, 10},
		},
	)

	// --- SMS (OTA) surfaces --------------------------------------------

	// OtaUecmLookups counts Nudm_UECM probe outcomes from OTA. The result
	// label is bounded: ok | not_found | malformed | resolver_error.
	// "not_found" is the *expected* default until UDM client lands —
	// triggers OTA's graceful Diameter fallback, not an alert.
	OtaUecmLookups = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbi_gateway",
			Name:      "ota_uecm_lookups_total",
			Help:      "Serving-SMSF (Nudm_UECM) lookup outcomes",
		},
		[]string{"result"},
	)

	// OtaSmsfSends counts Nsmsf_SMService SendSMS attempts dispatched via
	// the JetStream consumer. result: delivered | pending | failed | retries_exhausted |
	// client_error | bypassed | not_implemented.
	OtaSmsfSends = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbi_gateway",
			Name:      "ota_smsf_sends_total",
			Help:      "Nsmsf_SMService SendSMS dispatch outcomes",
		},
		[]string{"result"},
	)

	// OtaDeliveryEventsPublished counts ota.delivery.event publications by
	// the unified status enum (DELIVERED / FAILED / PENDING).
	OtaDeliveryEventsPublished = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbi_gateway",
			Name:      "ota_delivery_events_published_total",
			Help:      "Delivery events published to ota.delivery.event by status",
		},
		[]string{"status"},
	)

	// --- Audit -----------------------------------------------------------

	// AuditEvents counts audit.Log emissions by outcome:
	//   emitted  — accepted into the publisher queue (or slog fallback)
	//   dropped  — queue full; event lost (operator must size queue / NATS)
	AuditEvents = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbi_gateway",
			Name:      "audit_events_total",
			Help:      "Audit events emission outcomes",
		},
		[]string{"result"},
	)
)

// RecordRequest records HTTP request metrics
func RecordRequest(method, path, status string, duration float64) {
	RequestsTotal.WithLabelValues(method, path, status).Inc()
	RequestDuration.WithLabelValues(method, path).Observe(duration)
}

// RecordNatsRequest records NATS request metrics
func RecordNatsRequest(subject, status string, duration float64) {
	NatsRequestsTotal.WithLabelValues(subject, status).Inc()
	NatsRequestDuration.WithLabelValues(subject).Observe(duration)
}

// RecordError records an error occurrence
func RecordError(errorType, cause string) {
	ErrorsTotal.WithLabelValues(errorType, cause).Inc()
}

// SetNatsConnected sets NATS connection status
func SetNatsConnected(connected bool) {
	if connected {
		NatsConnectionStatus.Set(1)
	} else {
		NatsConnectionStatus.Set(0)
	}
}

// IncActiveRequests increments active request count
func IncActiveRequests() {
	ActiveRequests.Inc()
}

// DecActiveRequests decrements active request count
func DecActiveRequests() {
	ActiveRequests.Dec()
}

// RecordCallbackRetry records a callback retry attempt
func RecordCallbackRetry(status string) {
	CallbackRetries.WithLabelValues(status).Inc()
}

// RecordOAuthValidation records the outcome of an OAuth2 NF token check.
// result is "ok" or "fail"; reason is an oauth.FailReason value.
func RecordOAuthValidation(result, reason string) {
	OAuthValidations.WithLabelValues(result, reason).Inc()
}

// RecordOutboundDelivery records the outcome of one outbound delivery
// attempt set (i.e., one pass through the failover loop, possibly retried).
// result is one of: ok | failover | bypassed | exhausted | client_error | not_allowed |
// not_implemented.
func RecordOutboundDelivery(profile, result string) {
	OutboundDeliveries.WithLabelValues(profile, result).Inc()
}

// RecordJWKSRefresh counts a fetch of the NRF's JWKS and, when it succeeded, stamps its time.
func RecordJWKSRefresh(ok bool) {
	if !ok {
		OAuthJWKSRefreshes.WithLabelValues("error").Inc()
		return
	}
	OAuthJWKSRefreshes.WithLabelValues("ok").Inc()
	OAuthJWKSLastRefresh.SetToCurrentTime()
}

// SetJWKSKeys records how many verification keys the gateway holds.
func SetJWKSKeys(n int) {
	OAuthJWKSKeys.Set(float64(n))
}

// RecordOutboundEndpointSkip counts a callback URI not called; reason is resting or
// retry_after.
func RecordOutboundEndpointSkip(reason string) {
	OutboundEndpointSkips.WithLabelValues(reason).Inc()
}

// RecordOutboundPosition observes which endpoint index (0=primary) delivered.
func RecordOutboundPosition(position int) {
	OutboundEndpointPosition.Observe(float64(position))
}

// RecordOtaUecmLookup records the outcome of one Nudm_UECM probe from OTA.
func RecordOtaUecmLookup(result string) {
	OtaUecmLookups.WithLabelValues(result).Inc()
}

// RecordOtaSmsfSend records the outcome of one Nsmsf_SMService SendSMS dispatch.
func RecordOtaSmsfSend(result string) {
	OtaSmsfSends.WithLabelValues(result).Inc()
}

// RecordOtaDeliveryEvent records a publish to ota.delivery.event.
func RecordOtaDeliveryEvent(status string) {
	OtaDeliveryEventsPublished.WithLabelValues(status).Inc()
}

// RecordAuditEvent records the outcome of an audit.Log call.
// result is one of: emitted | dropped.
func RecordAuditEvent(result string) {
	AuditEvents.WithLabelValues(result).Inc()
}

// SetSecurityProtection records whether protection is on.
func SetSecurityProtection(protection string, on bool) {
	if on {
		SecurityProtection.WithLabelValues(protection).Set(1)
	} else {
		SecurityProtection.WithLabelValues(protection).Set(0)
	}
}
