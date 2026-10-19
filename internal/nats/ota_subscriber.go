// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nats

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	sbiclient "github.com/3eAI-Labs/sbi-ha-gateway-client"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers/outbound"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers/uecm"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/sbi"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Subjects and JetStream names of the OTA surfaces. They are part of the wire
// contract (sbiclient), so a rename is a contract change, not a local edit.
const (
	subjectUecmRequest   = sbiclient.SubjectUecmRequest
	subjectSmsfRequest   = sbiclient.SubjectSmsfSendRequest
	subjectDeliveryEvent = sbiclient.SubjectDeliveryEvent
	otaQueueGroup        = "sbi-gateway-ota"
	otaStreamName        = sbiclient.StreamSmsfSend
	otaConsumerName      = sbiclient.ConsumerSmsfSend

	// otaMaxDeliver is how many times JetStream delivers an SbiOtaMessage. A transient
	// failure on the last delivery is reported FAILED: nothing will try again.
	otaMaxDeliver = 3
)

// Envelopes of the OTA surfaces, defined by the wire contract.
type (
	NudmUecmMessage = sbiclient.NudmUecmMessage
	SbiOtaMessage   = sbiclient.SbiOtaMessage
	SbiHeader       = sbiclient.SbiHeader
	SbiRouting      = sbiclient.SbiRouting
	SS7PayloadView  = sbiclient.SS7PayloadView
	DeliveryEvent   = sbiclient.DeliveryEvent
)

// OTASubscriber wires the two NATS surfaces of the SMS (OTA) platform:
//
//  1. sbi.outbound.nudm.uecm.request — Core NATS request/reply (fail-fast,
//     no retry). OTA expects a reply within its probe budget; on timeout it
//     falls back to Diameter S6c. We do NOT retry here — slow / silent is
//     OTA's expected fallback trigger, not a defect.
//
//  2. sbi.outbound.nsmsf.send.request — JetStream WorkQueue (delete-after-ack).
//     We forward the SMS (an RP-DATA) via Nsmsf_SMService MtForwardSm to the resolved
//     SMSF FQDN, then publish a unified DeliveryEvent to ota.delivery.event with the
//     mobile station's report.
type OTASubscriber struct {
	conn     *nats.Conn
	js       jetstream.JetStream
	log      *slog.Logger
	resolver uecm.Resolver
	outbound outbound.Client
	uecmTime time.Duration
	nakDelay time.Duration // before JetStream redelivers after a transient failure

	uecmSub   *nats.Subscription
	consumeCx jetstream.ConsumeContext

	mu       sync.Mutex
	stopped  bool // set by Stop: no SMS is started after it
	inflight sync.WaitGroup
}

// OTAConfig bundles the wiring inputs main.go provides.
type OTAConfig struct {
	Resolver    uecm.Resolver   // resolver for Nudm_UECM lookups; never nil — use uecm.NewEmpty()
	Outbound    outbound.Client // how MtForwardSm reaches the SMSF
	UecmTimeout time.Duration   // total budget for handle-and-reply; default 3s
}

// NewOTASubscriber constructs an OTA-side subscriber. Call Start() to
// activate; Stop() drains and unsubscribes both surfaces.
func NewOTASubscriber(conn *nats.Conn, js jetstream.JetStream, log *slog.Logger, cfg OTAConfig) *OTASubscriber {
	if cfg.UecmTimeout <= 0 {
		cfg.UecmTimeout = 3 * time.Second
	}
	if cfg.Resolver == nil {
		cfg.Resolver = uecm.NewEmpty()
	}
	return &OTASubscriber{
		conn:     conn,
		js:       js,
		log:      log,
		resolver: cfg.Resolver,
		outbound: cfg.Outbound,
		uecmTime: cfg.UecmTimeout,
		nakDelay: 2 * time.Second,
	}
}

// Start opens both subscriptions. Returns the first error encountered;
// partial state is unwound (UECM subscription cleaned up if JetStream
// consumer setup fails).
func (s *OTASubscriber) Start(ctx context.Context) error {
	uecmSub, err := s.conn.QueueSubscribe(subjectUecmRequest, otaQueueGroup, s.handleUecm)
	if err != nil {
		return fmt.Errorf("subscribe %s: %w", subjectUecmRequest, err)
	}
	s.uecmSub = uecmSub

	if s.js != nil {
		if err := s.startSmsfConsumer(ctx); err != nil {
			_ = s.uecmSub.Unsubscribe()
			s.uecmSub = nil
			return err
		}
	}

	s.log.Info("OTA subscriber started",
		slog.String("uecm_subject", subjectUecmRequest),
		slog.String("smsf_subject", subjectSmsfRequest),
		slog.Bool("jetstream_enabled", s.js != nil),
	)
	return nil
}

// startSmsfConsumer creates-or-updates the JetStream pull consumer bound
// to OTA's pre-existing OTA_OUTBOUND stream (publisher side). We never
// create the stream — that's OTA's responsibility — but we DO create our
// own durable consumer so the stream name + subject filter stays declarative
// in our config.
func (s *OTASubscriber) startSmsfConsumer(ctx context.Context) error {
	consumer, err := s.js.CreateOrUpdateConsumer(ctx, otaStreamName, jetstream.ConsumerConfig{
		Durable:       otaConsumerName,
		FilterSubject: subjectSmsfRequest,
		AckPolicy:     jetstream.AckExplicitPolicy,
		MaxDeliver:    otaMaxDeliver,
	})
	if err != nil {
		return fmt.Errorf("create OTA SMSF consumer: %w", err)
	}
	cc, err := consumer.Consume(s.handleSmsfMsg)
	if err != nil {
		return fmt.Errorf("start consume: %w", err)
	}
	s.consumeCx = cc
	return nil
}

// Stop stops taking SMS and UECM requests and waits, until ctx ends, for the SMS being sent:
// cut off, it would be sent again when JetStream redelivers it. SMS already fetched but not
// started are left to JetStream, which redelivers them after the consumer's AckWait. Safe to
// call multiple times.
func (s *OTASubscriber) Stop(ctx context.Context) error {
	s.mu.Lock()
	s.stopped = true
	s.mu.Unlock()
	if s.consumeCx != nil {
		s.consumeCx.Stop()
		s.consumeCx = nil
	}
	var err error
	if s.uecmSub != nil {
		closed := s.uecmSub.StatusChanged(nats.SubscriptionClosed)
		if err = s.uecmSub.Drain(); err == nil {
			select {
			case <-closed:
			case <-ctx.Done():
				err = ctx.Err()
			}
		}
		s.uecmSub = nil
	}
	done := make(chan struct{})
	go func() {
		s.inflight.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err != nil {
		s.log.Warn("OTA subscriber did not stop cleanly", slog.Any("error", err))
	}
	return err
}

// --- Nudm_UECM (request/reply) -------------------------------------------

func (s *OTASubscriber) handleUecm(msg *nats.Msg) {
	var req NudmUecmMessage
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		s.log.Warn("OTA UECM: malformed request", slog.Any("error", err))
		metrics.RecordOtaUecmLookup("malformed")
		// No reply — OTA's probe will time out and fall back. This matches
		// the spec'd "graceful" behaviour better than synthesising a reply
		// from a payload we couldn't parse.
		return
	}

	if req.Operation != "GET_UE_CONTEXT" {
		s.log.Warn("OTA UECM: unsupported operation",
			slog.String("op", req.Operation),
			slog.String("correlation", req.CorrelationId),
		)
		s.replyUecm(msg, &NudmUecmMessage{
			MessageType:    "SBI_NUDM_UECM",
			Operation:      "RESPONSE",
			CorrelationId:  req.CorrelationId,
			HttpStatus:     400,
			ProblemDetails: `{"cause":"INVALID_OPERATION"}`,
		})
		metrics.RecordOtaUecmLookup("malformed")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.uecmTime)
	defer cancel()

	uecmCtx, err := s.resolver.Resolve(ctx, req.Msisdn)
	switch {
	case errors.Is(err, uecm.ErrNotFound):
		// The expected default until UDM client lands. Reply with 404 +
		// NF_NOT_FOUND so OTA's probe budget terminates immediately and
		// it falls back to Diameter without waiting for the timeout.
		s.replyUecm(msg, &NudmUecmMessage{
			MessageType:    "SBI_NUDM_UECM",
			Operation:      "RESPONSE",
			Msisdn:         req.Msisdn,
			CorrelationId:  req.CorrelationId,
			HttpStatus:     404,
			ProblemDetails: `{"cause":"NF_NOT_FOUND"}`,
		})
		metrics.RecordOtaUecmLookup("not_found")
	case err != nil:
		s.log.Error("OTA UECM: resolver error",
			slog.String("correlation", req.CorrelationId),
			slog.Any("error", err),
		)
		s.replyUecm(msg, &NudmUecmMessage{
			MessageType:    "SBI_NUDM_UECM",
			Operation:      "RESPONSE",
			Msisdn:         req.Msisdn,
			CorrelationId:  req.CorrelationId,
			HttpStatus:     503,
			ProblemDetails: `{"cause":"NF_CONGESTION"}`,
		})
		metrics.RecordOtaUecmLookup("resolver_error")
	default:
		s.replyUecm(msg, &NudmUecmMessage{
			MessageType:   "SBI_NUDM_UECM",
			Operation:     "RESPONSE",
			Msisdn:        req.Msisdn,
			CorrelationId: req.CorrelationId,
			Supi:          uecmCtx.Supi,
			SmsfFqdn:      uecmCtx.SmsfFqdn,
			SmsfPlmnId:    uecmCtx.SmsfPlmnId,
			HttpStatus:    200,
		})
		metrics.RecordOtaUecmLookup("ok")
	}
}

// replyUecm marshals + sends a reply on the original request's reply inbox.
// Failures here are logged but not retried — by the time msg.Respond fails
// the request has already passed OTA's probe budget.
func (s *OTASubscriber) replyUecm(msg *nats.Msg, body *NudmUecmMessage) {
	data, err := json.Marshal(body)
	if err != nil {
		s.log.Error("OTA UECM: marshal reply failed", slog.Any("error", err))
		return
	}
	if err := msg.Respond(data); err != nil {
		s.log.Warn("OTA UECM: respond failed (reply inbox likely closed)",
			slog.Any("error", err))
	}
}

// --- Nsmsf_SMService SendSMS (JetStream) ---------------------------------

func (s *OTASubscriber) handleSmsfMsg(msg jetstream.Msg) {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		_ = msg.Nak() // another gateway takes it now
		return
	}
	s.inflight.Add(1)
	s.mu.Unlock()
	defer s.inflight.Done()

	var req SbiOtaMessage
	if err := json.Unmarshal(msg.Data(), &req); err != nil {
		s.log.Warn("OTA SMSF: malformed message", slog.Any("error", err))
		metrics.RecordOtaSmsfSend("client_error")
		// Term to remove from the work queue — redelivery would loop on
		// the same parse failure and exhaust MaxDeliver pointlessly.
		_ = msg.Term()
		return
	}

	txID := txIDFromMetadata(req.Metadata)
	status, cause, report := s.dispatchSmsf(&req)
	meta := map[string]string{
		"supi":     req.Routing.Supi,
		"smsfFqdn": req.Routing.SmsfFqdn,
	}
	if report != nil {
		meta["deliveryReport"] = base64.StdEncoding.EncodeToString(report)
	}
	if status == sbiclient.DeliveryPending && lastDelivery(msg) {
		// OTA gets an end, not one more PENDING that nothing follows.
		meta["lastCause"] = cause
		status, cause = sbiclient.DeliveryFailed, "RETRIES_EXHAUSTED"
	}
	metrics.RecordOtaSmsfSend(metricsResultFor(status, cause))
	s.publishDelivery(DeliveryEvent{
		TransactionID: txID,
		Bearer:        "SBI",
		Status:        status,
		Cause:         cause,
		BearerMeta:    meta,
		Timestamp:     time.Now().UTC(),
	})

	// Ack policy: DELIVERED / FAILED → Ack (work done, the work queue drops it). Transient
	// failures → Nak with delay so JetStream redelivers (up to otaMaxDeliver).
	if status == sbiclient.DeliveryPending {
		_ = msg.NakWithDelay(s.nakDelay)
		return
	}
	_ = msg.Ack()
}

// lastDelivery reports whether JetStream will not deliver msg again.
func lastDelivery(msg jetstream.Msg) bool {
	md, err := msg.Metadata()
	return err == nil && md.NumDelivered >= otaMaxDeliver
}

// RP message types (TS 24.011 Table 8.3; bits 1-3 of the first octet).
const (
	rpDataNetworkToMS  = 0x01 // RP-DATA, network to mobile station
	rpAckMSToNetwork   = 0x02 // RP-ACK, mobile station to network
	rpErrorMSToNetwork = 0x04 // RP-ERROR, mobile station to network
)

// dispatchSmsf forwards the SMS to the resolved SMSF with Nsmsf_SMService MtForwardSm and
// classifies the result. Returns (status, cause) for the DeliveryEvent, and the mobile
// station's report from the response when there is one.
func (s *OTASubscriber) dispatchSmsf(req *SbiOtaMessage) (status, cause string, report []byte) {
	if req.Routing.SmsfFqdn == "" || req.Routing.Supi == "" {
		return "FAILED", "INVALID_ROUTING", nil
	}
	if req.Header.Service != "Nsmsf_SMService" ||
		(req.Header.Operation != "MtForwardSm" && req.Header.Operation != "SendSMS") {
		return "FAILED", "UNSUPPORTED_OPERATION", nil
	}
	// TS 29.540: the SMS goes to the SMSF as the binary part of a multipart/related body.
	// The gateway checks it is an RP-DATA towards the UE and sends it unchanged.
	rpData, err := base64.StdEncoding.DecodeString(req.Payload.Content)
	if req.Payload.Encoding != sbiclient.EncodingRPData || err != nil ||
		len(rpData) == 0 || rpData[0]&0x07 != rpDataNetworkToMS {
		return "FAILED", "PAYLOAD_NOT_RP_DATA", nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := s.outbound.Send(ctx, &outbound.Request{
		TargetNF:    "SMSF",
		CallbackURI: buildSmsfMtURI(req.Routing.SmsfFqdn, req.Routing.Supi),
		Service:     "nsmsf-sms",
		Operation:   "MtForwardSm",
		Multipart: &sbi.Multipart{
			JSON:       []byte(`{"smsPayload":{"contentId":"sms"}}`), // TS 29.577 SmsData
			Binary:     rpData,
			BinaryType: "application/vnd.3gpp.sms",
			ContentID:  "sms",
		},
	})
	switch {
	case err == nil:
		return deliveryOutcome(resp)
	case errors.Is(err, outbound.ErrBypassed):
		// Configured profile delegates elsewhere — treated as success
		// from our perspective, with cause="BYPASSED" so OTA dashboards
		// can tell the difference between a real delivery and a bypass.
		return "DELIVERED", "BYPASSED", nil
	case errors.Is(err, outbound.ErrMtcIwfNotImplemented),
		errors.Is(err, outbound.ErrScefNotImplemented):
		// Operator peering pending; permanent until config changes.
		return "FAILED", "PEERING_PENDING", nil
	case errors.Is(err, sbi.ErrDestinationNotAllowed):
		// OUTBOUND_ALLOWED_DESTINATIONS does not list the SMSF: permanent until it does.
		return "FAILED", "DESTINATION_NOT_ALLOWED", nil
	}

	// HTTP-level failure: classify retryability for the ack/nak decision.
	var httpErr *sbi.HTTPError
	if errors.As(err, &httpErr) {
		if httpErr.IsRetryable() {
			return "PENDING", fmt.Sprintf("HTTP_%d", httpErr.StatusCode), nil
		}
		return "FAILED", fmt.Sprintf("HTTP_%d", httpErr.StatusCode), nil
	}
	// Transport error (DNS, dial, TLS) — treat as transient (PENDING): JetStream
	// redelivers up to otaMaxDeliver, and the last failure is reported FAILED.
	return "PENDING", "TRANSPORT_ERROR", nil
}

// deliveryOutcome reads the mobile station's report in a MtForwardSm response (TS 29.577
// SmsDeliveryData, whose binary part is the report): RP-ACK is delivered, RP-ERROR failed
// with its cause value (TS 24.011 clause 8.2.5.4: length octet, then the cause in bits 1-7).
// A response without a recognisable report is failed: the gateway cannot tell OTA the SMS
// arrived.
func deliveryOutcome(resp *outbound.Response) (status, cause string, report []byte) {
	if resp == nil || resp.Multipart == nil || len(resp.Multipart.Binary) == 0 {
		return "FAILED", "INVALID_DELIVERY_REPORT", nil
	}
	report = resp.Multipart.Binary
	switch report[0] & 0x07 {
	case rpAckMSToNetwork:
		return "DELIVERED", "RP_ACK", report
	case rpErrorMSToNetwork:
		if len(report) >= 4 && report[2] >= 1 {
			return "FAILED", fmt.Sprintf("RP_CAUSE_%d", report[3]&0x7f), report
		}
	}
	return "FAILED", "INVALID_DELIVERY_REPORT", report
}

// publishDelivery sends the DeliveryEvent. Falls back to core-NATS publish
// when JetStream isn't configured — the delivery_event subject is part of
// OTA's stream filter but core publish still reaches their ingestion side
// for migration scenarios.
func (s *OTASubscriber) publishDelivery(ev DeliveryEvent) {
	data, err := json.Marshal(ev)
	if err != nil {
		s.log.Error("OTA delivery event marshal failed", slog.Any("error", err))
		return
	}
	if s.js != nil {
		if _, err := s.js.Publish(context.Background(), subjectDeliveryEvent, data); err != nil {
			s.log.Warn("OTA delivery event JS publish failed; falling back to core",
				slog.Any("error", err))
		} else {
			metrics.RecordOtaDeliveryEvent(ev.Status)
			return
		}
	}
	if err := s.conn.Publish(subjectDeliveryEvent, data); err != nil {
		s.log.Error("OTA delivery event core publish failed", slog.Any("error", err))
		return
	}
	metrics.RecordOtaDeliveryEvent(ev.Status)
}

// buildSmsfMtURI produces the Nsmsf_SMService MtForwardSm endpoint per TS 29.540 clause
// 5.2.2.5: POST {smsfFqdn}/nsmsf-sms/v2/ue-contexts/{supi}/send-mt-sms. ("sendsms" is
// UplinkSMS, the AMF's.) SUPI is path-escaped because real SUPIs (imsi-001..., suci-...)
// contain characters that need %-encoding in some forms.
func buildSmsfMtURI(smsfFqdn, supi string) string {
	scheme := "https"
	if !strings.Contains(smsfFqdn, "://") {
		smsfFqdn = scheme + "://" + smsfFqdn
	}
	return fmt.Sprintf("%s/nsmsf-sms/v2/ue-contexts/%s/send-mt-sms",
		strings.TrimRight(smsfFqdn, "/"),
		url.PathEscape(supi),
	)
}

// txIDFromMetadata extracts the transaction id OTA threads through metadata.
// Falls back to "unknown" so the DeliveryEvent always has a non-empty tx_id
// (OTA correlates downstream by it; "" would land in their orphan bucket).
func txIDFromMetadata(meta map[string]string) string {
	if meta == nil {
		return "unknown"
	}
	for _, k := range []string{"tx_id", "transactionId", "transaction_id"} {
		if v, ok := meta[k]; ok && v != "" {
			return v
		}
	}
	return "unknown"
}

// metricsResultFor maps the (status, cause) tuple to one of the bounded
// metric label values. Keeps cardinality flat at the metric layer while
// preserving cause detail in the DeliveryEvent itself.
func metricsResultFor(status, cause string) string {
	switch status {
	case "DELIVERED":
		if cause == "BYPASSED" {
			return "bypassed"
		}
		return "delivered"
	case "PENDING":
		return "pending"
	case "FAILED":
		switch cause {
		case "PEERING_PENDING":
			return "not_implemented"
		case "RETRIES_EXHAUSTED":
			return "retries_exhausted"
		case "INVALID_ROUTING", "UNSUPPORTED_OPERATION":
			return "client_error"
		default:
			return "failed"
		}
	}
	return "failed"
}
