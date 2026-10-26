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
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/audit"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers/outbound"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers/uecm"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/sbi"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Subjects and JetStream names of the SMS surfaces. They are part of the wire contract
// (sbiclient), so a rename is a contract change, not a local edit; the stream's name and the
// delivery events' subject are the operator's (SMSConfig).
const (
	subjectUecmRequest = sbiclient.SubjectUecmRequest
	subjectSmsfRequest = sbiclient.SubjectSmsfSendRequest
	smsQueueGroup      = "sbi-gateway-sms"
	smsConsumerName    = sbiclient.ConsumerSmsfSend

	// smsMaxDeliver is how many times JetStream delivers an SmsMessage. A transient
	// failure on the last delivery is reported FAILED: nothing will try again.
	smsMaxDeliver = 3
)

// Envelopes of the SMS surfaces, defined by the wire contract.
type (
	NudmUecmMessage = sbiclient.NudmUecmMessage
	SmsMessage      = sbiclient.SmsMessage
	SbiHeader       = sbiclient.SbiHeader
	SbiRouting      = sbiclient.SbiRouting
	SS7PayloadView  = sbiclient.SS7PayloadView
	DeliveryEvent   = sbiclient.DeliveryEvent
)

// SMSSubscriber wires the two NATS surfaces of an SMS platform:
//
//  1. sbi.outbound.nudm.uecm.request — Core NATS request/reply (fail-fast, no retry). The
//     platform expects a reply within its probe budget and, without one, may fall back to
//     another path (Diameter S6c, MAP): slow or silent is a fallback trigger, not a defect,
//     so the gateway does not retry.
//
//  2. sbi.outbound.nsmsf.send.request — JetStream WorkQueue (delete-after-ack). The SMS (an
//     RP-DATA) goes with Nsmsf_SMService MtForwardSm to the SMSF the message names, and a
//     DeliveryEvent with the mobile station's report goes to the delivery events' subject.
type SMSSubscriber struct {
	conn      *nats.Conn
	js        jetstream.JetStream
	log       *slog.Logger
	resolver  uecm.Resolver
	outbound  outbound.Client
	discovery Discovery
	uecmTime  time.Duration
	nakDelay  time.Duration // before JetStream redelivers after a transient failure
	stream    string        // the stream to create when no stream captures the SMS subject
	events    string        // the delivery events' subject
	eventsJS  bool          // a stream captured it at Start: publish through JetStream

	uecmSub   *nats.Subscription
	consumeCx jetstream.ConsumeContext

	mu       sync.Mutex
	stopped  bool // set by Stop: no SMS is started after it
	inflight sync.WaitGroup
}

// SMSConfig bundles the wiring inputs main.go provides.
type SMSConfig struct {
	Resolver    uecm.Resolver   // resolver for Nudm_UECM lookups; never nil — use uecm.NewEmpty()
	Outbound    outbound.Client // how MtForwardSm reaches the SMSF
	Discovery   Discovery       // finds an SMSF named by its instance ID; nil: SMS go to smsfFqdn
	UecmTimeout time.Duration   // total budget for handle-and-reply; default 3s
	// Stream names the stream that captures sbi.outbound.nsmsf.send.request, created when
	// no stream does; default sbiclient.StreamSmsfSend.
	Stream string
	// DeliveryEventSubject is where each SMS's DeliveryEvent goes; default
	// sbiclient.SubjectDeliveryEvent.
	DeliveryEventSubject string
}

// Discovery finds a producer's service by the producer's NF instance ID with the NRF
// (Nnrf_NFDiscovery, TS 29.510): an *nrf.Discovery.
type Discovery interface {
	// ServiceRoot returns the {apiRoot} of the service (e.g. nsmsf-sms, with version e.g.
	// v2 in its URIs) of the instance of type nfType with that ID.
	ServiceRoot(ctx context.Context, nfType, instanceID, service, version string) (string, error)
	// Unknown reports whether err is the NRF knowing no such instance offering the service.
	Unknown(err error) bool
	// Transient reports whether err may pass: the NRF did not answer, or not yet.
	Transient(err error) bool
}

// NewSMSSubscriber constructs the SMS surfaces' subscriber. Call Start() to activate;
// Stop() drains and unsubscribes both surfaces.
func NewSMSSubscriber(conn *nats.Conn, js jetstream.JetStream, log *slog.Logger, cfg SMSConfig) *SMSSubscriber {
	if cfg.UecmTimeout <= 0 {
		cfg.UecmTimeout = 3 * time.Second
	}
	if cfg.Resolver == nil {
		cfg.Resolver = uecm.NewEmpty()
	}
	if cfg.Stream == "" {
		cfg.Stream = sbiclient.StreamSmsfSend
	}
	if cfg.DeliveryEventSubject == "" {
		cfg.DeliveryEventSubject = sbiclient.SubjectDeliveryEvent
	}
	return &SMSSubscriber{
		conn:      conn,
		js:        js,
		log:       log,
		resolver:  cfg.Resolver,
		outbound:  cfg.Outbound,
		discovery: cfg.Discovery,
		uecmTime:  cfg.UecmTimeout,
		nakDelay:  2 * time.Second,
		stream:    cfg.Stream,
		events:    cfg.DeliveryEventSubject,
	}
}

// Start opens both subscriptions. Returns the first error encountered;
// partial state is unwound (UECM subscription cleaned up if JetStream
// consumer setup fails).
func (s *SMSSubscriber) Start(ctx context.Context) error {
	uecmSub, err := s.conn.QueueSubscribe(subjectUecmRequest, smsQueueGroup, s.handleUecm)
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

	s.log.Info("SMS subscriber started",
		slog.String("uecm_subject", subjectUecmRequest),
		slog.String("smsf_subject", subjectSmsfRequest),
		slog.String("delivery_event_subject", s.events),
		slog.Bool("jetstream_enabled", s.js != nil),
	)
	return nil
}

// startSmsfConsumer creates-or-updates the gateway's durable pull consumer on the stream that
// captures the SMS subject: the one that already does, whatever its name (an SMS platform may
// own it), else s.stream, created (smsStream).
func (s *SMSSubscriber) startSmsfConsumer(ctx context.Context) error {
	stream, err := s.smsStream(ctx)
	if err != nil {
		return err
	}
	// Without a stream on the delivery events' subject a JetStream publish waits for one
	// (half a second, measured) before failing: publish them without JetStream then.
	_, err = s.js.StreamNameBySubject(ctx, s.events)
	s.eventsJS = err == nil
	consumer, err := s.js.CreateOrUpdateConsumer(ctx, stream, jetstream.ConsumerConfig{
		Durable:       smsConsumerName,
		FilterSubject: subjectSmsfRequest,
		AckPolicy:     jetstream.AckExplicitPolicy,
		MaxDeliver:    smsMaxDeliver,
	})
	if err != nil {
		return fmt.Errorf("create the SMSF consumer on stream %s: %w", stream, err)
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
func (s *SMSSubscriber) Stop(ctx context.Context) error {
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
		s.log.Warn("SMS subscriber did not stop cleanly", slog.Any("error", err))
	}
	return err
}

// --- Nudm_UECM (request/reply) -------------------------------------------

func (s *SMSSubscriber) handleUecm(msg *nats.Msg) {
	var req NudmUecmMessage
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		s.log.Warn("UECM lookup: malformed request", slog.Any("error", err))
		metrics.RecordSMSUecmLookup("malformed")
		// No reply: the platform's probe times out and it falls back, rather than acting on a
		// reply synthesised from a payload that could not be parsed.
		return
	}

	if req.Operation != "GET_UE_CONTEXT" {
		s.log.Warn("UECM lookup: unsupported operation",
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
		metrics.RecordSMSUecmLookup("malformed")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.uecmTime)
	defer cancel()

	uecmCtx, err := s.resolver.Resolve(ctx, req.Msisdn)
	switch {
	case errors.Is(err, uecm.ErrNotFound):
		// No SMSF known for the MSISDN: 404 NF_NOT_FOUND ends the platform's probe at once, so
		// that it falls back without waiting for its timeout.
		s.replyUecm(msg, &NudmUecmMessage{
			MessageType:    "SBI_NUDM_UECM",
			Operation:      "RESPONSE",
			Msisdn:         req.Msisdn,
			CorrelationId:  req.CorrelationId,
			HttpStatus:     404,
			ProblemDetails: `{"cause":"NF_NOT_FOUND"}`,
		})
		metrics.RecordSMSUecmLookup("not_found")
	case err != nil:
		s.log.Error("UECM lookup: resolver error",
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
		metrics.RecordSMSUecmLookup("resolver_error")
	default:
		s.replyUecm(msg, &NudmUecmMessage{
			MessageType:    "SBI_NUDM_UECM",
			Operation:      "RESPONSE",
			Msisdn:         req.Msisdn,
			CorrelationId:  req.CorrelationId,
			Supi:           uecmCtx.Supi,
			SmsfFqdn:       uecmCtx.SmsfFqdn,
			SmsfInstanceId: uecmCtx.SmsfInstanceId,
			SmsfPlmnId:     uecmCtx.SmsfPlmnId,
			HttpStatus:     200,
		})
		metrics.RecordSMSUecmLookup("ok")
	}
}

// replyUecm marshals + sends a reply on the original request's reply inbox.
// Failures here are logged but not retried — by the time msg.Respond fails
// the request has already passed the platform's probe budget.
func (s *SMSSubscriber) replyUecm(msg *nats.Msg, body *NudmUecmMessage) {
	data, err := json.Marshal(body)
	if err != nil {
		s.log.Error("UECM lookup: marshal reply failed", slog.Any("error", err))
		return
	}
	if err := msg.Respond(data); err != nil {
		s.log.Warn("UECM lookup: respond failed (reply inbox likely closed)",
			slog.Any("error", err))
	}
}

// --- Nsmsf_SMService SendSMS (JetStream) ---------------------------------

func (s *SMSSubscriber) handleSmsfMsg(msg jetstream.Msg) {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		_ = msg.Nak() // another gateway takes it now
		return
	}
	s.inflight.Add(1)
	s.mu.Unlock()
	defer s.inflight.Done()

	var req SmsMessage
	if err := json.Unmarshal(msg.Data(), &req); err != nil {
		s.log.Warn("SMS: malformed message", slog.Any("error", err))
		metrics.RecordSMSSmsfSend("client_error")
		// Term to remove from the work queue — redelivery would loop on
		// the same parse failure and exhaust MaxDeliver pointlessly.
		_ = msg.Term()
		return
	}

	txID := txIDFromMetadata(req.Metadata)
	status, cause, uri, report := s.dispatchSmsf(&req)
	meta := map[string]string{
		"supi":     req.Routing.Supi,
		"smsfFqdn": req.Routing.SmsfFqdn,
	}
	if req.Routing.SmsfInstanceId != "" {
		meta["smsfInstanceId"] = req.Routing.SmsfInstanceId
	}
	if uri == "" { // not sent: the target as the message names it
		uri = buildSmsfMtURI(req.Routing.SmsfFqdn, req.Routing.Supi)
	}
	if report != nil {
		meta["deliveryReport"] = base64.StdEncoding.EncodeToString(report)
	}
	if status == sbiclient.DeliveryPending && lastDelivery(msg) {
		// The platform gets an end, not one more PENDING that nothing follows.
		meta["lastCause"] = cause
		status, cause = sbiclient.DeliveryFailed, "RETRIES_EXHAUSTED"
	}
	metrics.RecordSMSSmsfSend(metricsResultFor(status, cause))
	outcome := audit.Success
	if status != sbiclient.DeliveryDelivered {
		outcome = audit.Failed
	}
	audit.Action(context.Background(), "MtForwardSm", "nsmsf-sms", req.Routing.Supi,
		endpointKey(uri), outcome, cause)
	s.publishDelivery(DeliveryEvent{
		TransactionID: txID,
		Bearer:        "SBI",
		Status:        status,
		Cause:         cause,
		BearerMeta:    meta,
		Timestamp:     time.Now().UTC(),
	})

	// Ack policy: DELIVERED / FAILED → Ack (work done, the work queue drops it). Transient
	// failures → Nak with delay so JetStream redelivers (up to smsMaxDeliver).
	if status == sbiclient.DeliveryPending {
		_ = msg.NakWithDelay(s.nakDelay)
		return
	}
	_ = msg.Ack()
}

// lastDelivery reports whether JetStream will not deliver msg again.
func lastDelivery(msg jetstream.Msg) bool {
	md, err := msg.Metadata()
	return err == nil && md.NumDelivered >= smsMaxDeliver
}

// RP message types (TS 24.011 Table 8.3; bits 1-3 of the first octet).
const (
	rpDataNetworkToMS  = 0x01 // RP-DATA, network to mobile station
	rpAckMSToNetwork   = 0x02 // RP-ACK, mobile station to network
	rpErrorMSToNetwork = 0x04 // RP-ERROR, mobile station to network
)

// dispatchSmsf forwards the SMS to the resolved SMSF with Nsmsf_SMService MtForwardSm and
// classifies the result. Returns (status, cause) for the DeliveryEvent, the URI the SMS went
// to ("" when it went nowhere), and the mobile station's report from the response when
// there is one.
func (s *SMSSubscriber) dispatchSmsf(req *SmsMessage) (status, cause, uri string, report []byte) {
	r := req.Routing
	discover := r.SmsfInstanceId != "" && s.discovery != nil
	if r.Supi == "" || (r.SmsfFqdn == "" && !discover) {
		return "FAILED", "INVALID_ROUTING", "", nil
	}
	if req.Header.Service != "Nsmsf_SMService" ||
		(req.Header.Operation != "MtForwardSm" && req.Header.Operation != "SendSMS") {
		return "FAILED", "UNSUPPORTED_OPERATION", "", nil
	}
	// TS 29.540: the SMS goes to the SMSF as the binary part of a multipart/related body.
	// The gateway checks it is an RP-DATA towards the UE and sends it unchanged.
	rpData, err := base64.StdEncoding.DecodeString(req.Payload.Content)
	if req.Payload.Encoding != sbiclient.EncodingRPData || err != nil ||
		len(rpData) == 0 || rpData[0]&0x07 != rpDataNetworkToMS {
		return "FAILED", "PAYLOAD_NOT_RP_DATA", "", nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	root := r.SmsfFqdn
	access := sbi.Access{Scope: "nsmsf-sms", TargetNfType: "SMSF"} // TS29540_Nsmsf_SMService.yaml security
	if discover {
		// The SMSF as the UDM knows it, by instance ID (TS 29.503 SmsfRegistration): its
		// address is the NRF's, and the token is for it alone.
		if root, err = s.discovery.ServiceRoot(ctx, "SMSF", r.SmsfInstanceId, "nsmsf-sms", "v2"); err != nil {
			s.log.Warn("SMSF discovery failed",
				slog.String("smsf_instance_id", r.SmsfInstanceId), slog.Any("error", err))
			switch {
			case s.discovery.Unknown(err):
				// No registered SMSF with that ID offers nsmsf-sms v2: the registration the
				// SMS platform was given is stale. Its other paths may reach the UE.
				return "FAILED", "SMSF_NOT_FOUND", "", nil
			case s.discovery.Transient(err):
				return "PENDING", "DISCOVERY_FAILED", "", nil
			}
			return "FAILED", "DISCOVERY_FAILED", "", nil
		}
		access.TargetNfInstanceId = r.SmsfInstanceId
	}
	uri = buildSmsfMtURI(root, r.Supi)
	status, cause, report = s.forwardSm(ctx, uri, access, rpData)
	return status, cause, uri, report
}

// forwardSm sends MtForwardSm to uri and classifies the result.
func (s *SMSSubscriber) forwardSm(ctx context.Context, uri string, access sbi.Access, rpData []byte) (status, cause string, report []byte) {
	resp, err := s.outbound.Send(ctx, &outbound.Request{
		TargetNF:    "SMSF",
		CallbackURI: uri,
		Service:     "nsmsf-sms",
		Operation:   "MtForwardSm",
		Access:      access,
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
		// Configured profile delegates elsewhere — treated as success from the gateway's
		// perspective, with cause="BYPASSED" so that the platform can tell a real delivery
		// from a bypass.
		return "DELIVERED", "BYPASSED", nil
	case errors.Is(err, outbound.ErrMtcIwfNotImplemented),
		errors.Is(err, outbound.ErrScefNotImplemented):
		// Operator peering pending; permanent until config changes.
		return "FAILED", "PEERING_PENDING", nil
	case errors.Is(err, sbi.ErrDestinationNotAllowed):
		// OUTBOUND_ALLOWED_DESTINATIONS does not list the SMSF: permanent until it does.
		return "FAILED", "DESTINATION_NOT_ALLOWED", nil
	case errors.Is(err, sbi.ErrNoAccessToken):
		// The SMSF asks for a token the NRF did not give: transient, the NRF may later.
		return "PENDING", "NO_ACCESS_TOKEN", nil
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
	// redelivers up to smsMaxDeliver, and the last failure is reported FAILED.
	return "PENDING", "TRANSPORT_ERROR", nil
}

// deliveryOutcome reads the mobile station's report in a MtForwardSm response (TS 29.577
// SmsDeliveryData, whose binary part is the report): RP-ACK is delivered, RP-ERROR failed
// with its cause value (TS 24.011 clause 8.2.5.4: length octet, then the cause in bits 1-7).
// A response without a recognisable report is failed: the gateway cannot tell the platform
// the SMS arrived.
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

// publishDelivery sends the DeliveryEvent: through JetStream, acknowledged, when a stream
// captured the subject at Start; as a core NATS publish when none did, or JetStream fails, so
// that a subscriber still gets it.
func (s *SMSSubscriber) publishDelivery(ev DeliveryEvent) {
	data, err := json.Marshal(ev)
	if err != nil {
		s.log.Error("delivery event marshal failed", slog.Any("error", err))
		return
	}
	if s.js != nil && s.eventsJS {
		_, err := s.js.Publish(context.Background(), s.events, data)
		if err == nil {
			metrics.RecordSMSDeliveryEvent(ev.Status)
			return
		}
		s.log.Warn("delivery event JetStream publish failed; published without JetStream",
			slog.Any("error", err))
	}
	if err := s.conn.Publish(s.events, data); err != nil {
		s.log.Error("delivery event publish failed", slog.Any("error", err))
		return
	}
	metrics.RecordSMSDeliveryEvent(ev.Status)
}

// smsStream returns the name of the stream that captures the SMS subject. When none does it
// creates s.stream, a work queue with one replica on file storage, and says so: an operator
// wanting replicas or limits creates the stream beforehand. Another replica creating it at
// the same moment is no error.
func (s *SMSSubscriber) smsStream(ctx context.Context) (string, error) {
	name, err := s.js.StreamNameBySubject(ctx, subjectSmsfRequest)
	if err == nil {
		return name, nil
	}
	if !errors.Is(err, jetstream.ErrStreamNotFound) {
		return "", fmt.Errorf("look up the stream of %s: %w", subjectSmsfRequest, err)
	}
	_, err = s.js.CreateStream(ctx, jetstream.StreamConfig{
		Name:      s.stream,
		Subjects:  []string{subjectSmsfRequest},
		Retention: jetstream.WorkQueuePolicy,
		Storage:   jetstream.FileStorage,
		Replicas:  1,
	})
	switch {
	case errors.Is(err, jetstream.ErrStreamNameAlreadyInUse):
		return s.stream, nil
	case err != nil:
		return "", fmt.Errorf("create stream %s for %s: %w", s.stream, subjectSmsfRequest, err)
	}
	s.log.Warn("Created the SMS stream: a work queue with one replica; create it beforehand for more",
		slog.String("stream", s.stream), slog.String("subject", subjectSmsfRequest))
	return s.stream, nil
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

// txIDFromMetadata extracts the transaction id the platform threads through metadata.
// Falls back to "unknown" so the DeliveryEvent always has a non-empty tx_id (a platform that
// correlates by it would otherwise file the event as an orphan).
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
