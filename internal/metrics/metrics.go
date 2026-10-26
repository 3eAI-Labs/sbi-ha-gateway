// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	cgaudit "github.com/3eAI-Labs/sbi-ha-gateway/internal/platform/audit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"time"
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

	// TLSCertificateExpiry is the NotAfter of each certificate the gateway presents, as Unix
	// time: certificate sbi (the SBI and admin ports) or outbound (callbacks, SMSF, NRF).
	TLSCertificateExpiry = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "sbi_gateway",
			Name:      "tls_certificate_expiry_timestamp_seconds",
			Help:      "Unix time a certificate the gateway presents expires",
		},
		[]string{"certificate"},
	)

	// TLSHandshakeFailures counts TLS handshakes a port did not complete: port sbi or admin.
	TLSHandshakeFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbi_gateway",
			Name:      "tls_handshake_failures_total",
			Help:      "TLS handshakes not completed, by port",
		},
		[]string{"port"},
	)

	// NatsEvents counts NATS connection events: disconnected, reconnected, slow_consumer
	// (messages dropped because a subscription fell behind), error.
	NatsEvents = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbi_gateway",
			Name:      "nats_events_total",
			Help:      "NATS connection events",
		},
		[]string{"event"},
	)

	// CallbackRetries counts notification attempts after a failed one, by what failed last:
	// status 5xx, 429 or transport.
	CallbackRetries = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbi_gateway",
			Name:      "callback_retries_total",
			Help:      "Notification attempts after a failed one, by the last failure",
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

	// --- SMS surfaces ----------------------------------------------------

	// SMSUecmLookups counts the serving-SMSF lookups an SMS platform asks. The result
	// label is bounded: ok | not_found | malformed | resolver_error. "not_found" is
	// expected while no resolver file lists the subscriber: the platform falls back to
	// Diameter or MAP, which is no reason to alert.
	SMSUecmLookups = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbi_gateway",
			Name:      "sms_uecm_lookups_total",
			Help:      "Serving-SMSF (Nudm_UECM) lookup outcomes",
		},
		[]string{"result"},
	)

	// SMSSmsfSends counts Nsmsf_SMService MtForwardSm attempts dispatched via
	// the JetStream consumer. result: delivered | pending | failed | retries_exhausted |
	// client_error | bypassed | not_implemented.
	SMSSmsfSends = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbi_gateway",
			Name:      "sms_smsf_sends_total",
			Help:      "Nsmsf_SMService MtForwardSm dispatch outcomes",
		},
		[]string{"result"},
	)

	// SMSDeliveryEventsPublished counts DeliveryEvent publications by
	// the unified status enum (DELIVERED / FAILED / PENDING).
	SMSDeliveryEventsPublished = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbi_gateway",
			Name:      "sms_delivery_events_published_total",
			Help:      "SMS delivery events published by status",
		},
		[]string{"status"},
	)

	// --- NRF registration (TS 29.510 Nnrf_NFManagement) -------------------

	// NRFRequests counts the gateway's requests to the NRF by operation (register,
	// heartbeat, retrieve, deregister; token, an access token request; discover, an
	// NFDiscovery search; subscribe, subscription_update, unsubscribe, NFStatusSubscribe's)
	// and result: the HTTP status, or "error" when none came back.
	NRFRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbi_gateway",
			Name:      "nrf_requests_total",
			Help:      "Requests to the NRF (NFManagement, access tokens, NFDiscovery, NFStatusSubscribe) by operation and result (HTTP status, or error without one)",
		},
		[]string{"nf_type", "operation", "result"},
	)

	// NRFNotifications counts the NRF's notifications to the gateway's subscriptions
	// (NFStatusNotify) by event (NF_DEREGISTERED, NF_PROFILE_CHANGED, NF_REGISTERED, other;
	// empty when the notification could not be read) and result: accepted,
	// unknown_subscription (answered 404), malformed, relay_failed (the replica that
	// subscribed could not be reached over NATS).
	NRFNotifications = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sbi_gateway",
			Name:      "nrf_notifications_total",
			Help:      "NRF notifications to the gateway's subscriptions by event and result",
		},
		[]string{"event", "result"},
	)

	// NRFRegistered is 1 per NF profile while this pod holds it registered: after the
	// NRF accepted its registration and until it answers that it does not know the instance.
	NRFRegistered = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "sbi_gateway",
			Name:      "nrf_registered",
			Help:      "1 while the NF profile is registered with the NRF as far as this pod knows",
		},
		[]string{"nf_type"},
	)

	// NRFLastContact is when the NRF last accepted a registration or heartbeat of the NF
	// profile from this pod (Unix seconds).
	NRFLastContact = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "sbi_gateway",
			Name:      "nrf_last_contact_timestamp_seconds",
			Help:      "When the NRF last accepted this pod's registration or heartbeat of the NF profile",
		},
		[]string{"nf_type"},
	)

	// --- Audit -----------------------------------------------------------

	// AuditEvents counts audit.Log emissions by outcome:
	//   emitted  — accepted into the publisher queue (or slog fallback)
	//   dropped  — queue full; event lost (operator must size queue / NATS)
	// AuditPublishFailures counts audit events NATS refused; each was logged instead, whole.
	AuditPublishFailures = promauto.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "sbi_gateway",
		Name:      "audit_publish_failures_total",
		Help:      "Audit events the publisher refused (logged instead)",
	}, func() float64 { return float64(cgaudit.PublishFailures()) })

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

// SetCertificateExpiry records when certificate expires.
func SetCertificateExpiry(certificate string, notAfter time.Time) {
	TLSCertificateExpiry.WithLabelValues(certificate).Set(float64(notAfter.Unix()))
}

// RecordTLSHandshakeFailure counts a TLS handshake port did not complete.
func RecordTLSHandshakeFailure(port string) {
	TLSHandshakeFailures.WithLabelValues(port).Inc()
}

// RecordNatsEvent counts a NATS connection event.
func RecordNatsEvent(event string) {
	NatsEvents.WithLabelValues(event).Inc()
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

// RecordSMSUecmLookup records the outcome of one serving-SMSF lookup.
func RecordSMSUecmLookup(result string) {
	SMSUecmLookups.WithLabelValues(result).Inc()
}

// RecordSMSSmsfSend records the outcome of one Nsmsf_SMService SendSMS dispatch.
func RecordSMSSmsfSend(result string) {
	SMSSmsfSends.WithLabelValues(result).Inc()
}

// RecordSMSDeliveryEvent records a DeliveryEvent publication.
func RecordSMSDeliveryEvent(status string) {
	SMSDeliveryEventsPublished.WithLabelValues(status).Inc()
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

// RecordNRFRequest counts one request to the NRF; result is the HTTP status or "error".
// A success also stamps the last contact, but for a deregistration or an access token.
func RecordNRFRequest(nfType, operation, result string, ok bool) {
	NRFRequests.WithLabelValues(nfType, operation, result).Inc()
	if ok && operation != "deregister" && operation != "token" {
		NRFLastContact.WithLabelValues(nfType).SetToCurrentTime()
	}
}

// RecordNRFNotification counts one NRF notification; an event the NRF API does not define
// counts as other.
func RecordNRFNotification(event, result string) {
	switch event {
	case "", "NF_DEREGISTERED", "NF_PROFILE_CHANGED", "NF_REGISTERED":
	default:
		event = "other"
	}
	NRFNotifications.WithLabelValues(event, result).Inc()
}

// SetNRFRegistered records whether the NF profile is registered as far as this pod knows.
func SetNRFRegistered(nfType string, registered bool) {
	v := 0.0
	if registered {
		v = 1
	}
	NRFRegistered.WithLabelValues(nfType).Set(v)
}
