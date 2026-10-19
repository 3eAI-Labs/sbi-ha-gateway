// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nats

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sbiclient "github.com/3eAI-Labs/sbi-ha-gateway-client"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers/outbound"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers/uecm"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/sbi"
	natsserver "github.com/nats-io/nats-server/v2/server"
	gnats "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func runOtaServer(t *testing.T) (*natsserver.Server, *gnats.Conn) {
	t.Helper()
	srv, err := natsserver.NewServer(&natsserver.Options{
		Port:      -1,
		JetStream: true,
		StoreDir:  t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats not ready")
	}
	conn, err := gnats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	return srv, conn
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// stubResolver returns a fixed context for one MSISDN, ErrNotFound otherwise.
type stubResolver struct {
	target string
	ctx    *uecm.Context
	err    error
}

func (s stubResolver) Resolve(_ context.Context, msisdn string) (*uecm.Context, error) {
	if s.err != nil {
		return nil, s.err
	}
	if msisdn == s.target {
		return s.ctx, nil
	}
	return nil, uecm.ErrNotFound
}

// stubOutbound captures Send calls and returns scripted responses.
type stubOutbound struct {
	calls []outbound.Request
	resp  *outbound.Response
	err   error
}

func (s *stubOutbound) Profile() outbound.Profile { return outbound.ProfileSBIDirect }
func (s *stubOutbound) Send(_ context.Context, r *outbound.Request) (*outbound.Response, error) {
	s.calls = append(s.calls, *r)
	return s.resp, s.err
}

// --- buildSmsfSendURI -----------------------------------------------------

func TestBuildSmsfMtURI(t *testing.T) {
	cases := []struct {
		fqdn, supi, want string
	}{
		{"smsf-1.5gc.tr", "imsi-286010000000001",
			"https://smsf-1.5gc.tr/nsmsf-sms/v2/ue-contexts/imsi-286010000000001/send-mt-sms"},
		// Already-schemed FQDN must NOT be double-prefixed.
		{"http://smsf-1.5gc.tr:8080", "imsi-001",
			"http://smsf-1.5gc.tr:8080/nsmsf-sms/v2/ue-contexts/imsi-001/send-mt-sms"},
		// Trailing slash on FQDN trimmed; SUPI escaped.
		{"https://smsf-1.5gc.tr/", "suci-0-001-01-0-0-0-12345",
			"https://smsf-1.5gc.tr/nsmsf-sms/v2/ue-contexts/suci-0-001-01-0-0-0-12345/send-mt-sms"},
	}
	for _, c := range cases {
		if got := buildSmsfMtURI(c.fqdn, c.supi); got != c.want {
			t.Errorf("buildSmsfMtURI(%q, %q) = %q, want %q", c.fqdn, c.supi, got, c.want)
		}
	}
}

// --- UECM request/reply ---------------------------------------------------

func TestUecm_HappyPath_RepliesWithContext(t *testing.T) {
	srv, conn := runOtaServer(t)
	defer srv.Shutdown()
	defer conn.Close()

	resolver := stubResolver{
		target: "905551234567",
		ctx: &uecm.Context{
			Supi:       "imsi-286010000000001",
			SmsfFqdn:   "smsf-1.5gc.tr",
			SmsfPlmnId: "28601",
		},
	}
	sub := NewOTASubscriber(conn, nil, quietLogger(), OTAConfig{
		Resolver: resolver,
		Outbound: &stubOutbound{},
	})
	if err := sub.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Stop(context.Background()) }()

	req := NudmUecmMessage{
		MessageType:   "SBI_NUDM_UECM",
		Operation:     "GET_UE_CONTEXT",
		Msisdn:        "905551234567",
		CorrelationId: "test-corr-1",
	}
	body, _ := json.Marshal(req)
	resp, err := conn.Request(subjectUecmRequest, body, 2*time.Second)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}

	var got NudmUecmMessage
	if err := json.Unmarshal(resp.Data, &got); err != nil {
		t.Fatal(err)
	}
	if got.HttpStatus != 200 || got.Supi != "imsi-286010000000001" || got.SmsfFqdn != "smsf-1.5gc.tr" {
		t.Errorf("unexpected reply: %+v", got)
	}
	if got.CorrelationId != "test-corr-1" {
		t.Errorf("correlation id not echoed: %q", got.CorrelationId)
	}
}

func TestUecm_NotFound_RepliesNF_NOT_FOUND(t *testing.T) {
	srv, conn := runOtaServer(t)
	defer srv.Shutdown()
	defer conn.Close()

	sub := NewOTASubscriber(conn, nil, quietLogger(), OTAConfig{
		Resolver: uecm.NewEmpty(), // production default — always NF_NOT_FOUND
		Outbound: &stubOutbound{},
	})
	_ = sub.Start(context.Background())
	defer func() { _ = sub.Stop(context.Background()) }()

	body, _ := json.Marshal(NudmUecmMessage{
		MessageType:   "SBI_NUDM_UECM",
		Operation:     "GET_UE_CONTEXT",
		Msisdn:        "905551234567",
		CorrelationId: "c2",
	})
	resp, err := conn.Request(subjectUecmRequest, body, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var got NudmUecmMessage
	_ = json.Unmarshal(resp.Data, &got)
	if got.HttpStatus != 404 {
		t.Errorf("HttpStatus = %d, want 404", got.HttpStatus)
	}
	if got.ProblemDetails != `{"cause":"NF_NOT_FOUND"}` {
		t.Errorf("ProblemDetails = %q", got.ProblemDetails)
	}
}

func TestUecm_UnsupportedOp_Replies400(t *testing.T) {
	srv, conn := runOtaServer(t)
	defer srv.Shutdown()
	defer conn.Close()

	sub := NewOTASubscriber(conn, nil, quietLogger(), OTAConfig{
		Resolver: uecm.NewEmpty(),
		Outbound: &stubOutbound{},
	})
	_ = sub.Start(context.Background())
	defer func() { _ = sub.Stop(context.Background()) }()

	body, _ := json.Marshal(NudmUecmMessage{
		MessageType:   "SBI_NUDM_UECM",
		Operation:     "DELETE_UE_CONTEXT", // not supported
		CorrelationId: "c3",
	})
	resp, err := conn.Request(subjectUecmRequest, body, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var got NudmUecmMessage
	_ = json.Unmarshal(resp.Data, &got)
	if got.HttpStatus != 400 {
		t.Errorf("HttpStatus = %d, want 400", got.HttpStatus)
	}
}

func TestUecm_MalformedRequest_NoReply(t *testing.T) {
	// Garbage payload → no reply → OTA's probe budget expires and falls
	// back to Diameter. Asserting "no reply within 200ms" is the contract.
	srv, conn := runOtaServer(t)
	defer srv.Shutdown()
	defer conn.Close()

	sub := NewOTASubscriber(conn, nil, quietLogger(), OTAConfig{
		Resolver: uecm.NewEmpty(),
		Outbound: &stubOutbound{},
	})
	_ = sub.Start(context.Background())
	defer func() { _ = sub.Stop(context.Background()) }()

	_, err := conn.Request(subjectUecmRequest, []byte("not json"), 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout (no reply); got success")
	}
}

// --- SMSF SendSMS (JetStream) --------------------------------------------

// setupOtaStream creates the JetStream stream the OTA team owns in
// production. Required so our consumer has something to bind to in tests.
func setupOtaStream(t *testing.T, conn *gnats.Conn) {
	t.Helper()
	c := &Client{conn: conn}
	js, err := c.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = js.CreateStream(ctx, jetstream.StreamConfig{
		Name: otaStreamName,
		Subjects: []string{
			"sbi.outbound.nsmsf.>",
			"ota.delivery.>",
		},
		Retention: jetstream.WorkQueuePolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
}

// testRPData is an RP-DATA towards the UE (TS 24.011 clause 7.3.1.1): MTI 001, message
// reference 7, a Service Centre address, an empty destination, and a 4-octet TPDU.
var testRPData = []byte{0x01, 0x07, 0x04, 0x91, 0x09, 0x55, 0xf1, 0x00, 0x04, 0x04, 0x0a, 0x0b, 0x0c}

func rpDataMessage(smsfURL string) []byte {
	body, _ := json.Marshal(SbiOtaMessage{
		Header:   SbiHeader{Service: "Nsmsf_SMService", Operation: "MtForwardSm", Version: "v2"},
		Routing:  SbiRouting{Supi: "imsi-001", SmsfFqdn: smsfURL},
		Payload:  SS7PayloadView{Encoding: sbiclient.EncodingRPData, Content: base64.StdEncoding.EncodeToString(testRPData)},
		Metadata: map[string]string{"tx_id": "tx-abc"},
	})
	return body
}

// sendThroughSmsf publishes message to the SMSF work queue with smsf as the SMSF and
// returns the DeliveryEvent the gateway publishes.
func sendThroughSmsf(t *testing.T, smsf http.Handler, message func(smsfURL string) []byte) DeliveryEvent {
	t.Helper()
	srv, conn := runOtaServer(t)
	t.Cleanup(srv.Shutdown)
	t.Cleanup(conn.Close)
	setupOtaStream(t, conn)
	httpServer := httptest.NewServer(smsf)
	t.Cleanup(httpServer.Close)

	amf := sbi.NewAmfClient()
	amf.Client.Transport = http.DefaultTransport
	out, _ := outbound.New(outbound.ProfileSBIDirect, amf)
	c := &Client{conn: conn}
	js, _ := c.JetStream()
	sub := NewOTASubscriber(conn, js, quietLogger(), OTAConfig{Resolver: uecm.NewEmpty(), Outbound: out})
	if err := sub.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Stop(context.Background()) })

	deliveries := make(chan DeliveryEvent, 1)
	if _, err := conn.Subscribe(subjectDeliveryEvent, func(msg *gnats.Msg) {
		var ev DeliveryEvent
		_ = json.Unmarshal(msg.Data, &ev)
		deliveries <- ev
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(context.Background(), subjectSmsfRequest, message(httpServer.URL)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	select {
	case ev := <-deliveries:
		return ev
	case <-time.After(3 * time.Second):
		t.Fatal("no delivery event published within 3s")
	}
	return DeliveryEvent{}
}

// smsfAnswering is an SMSF that checks the MtForwardSm request (TS 29.540: POST
// .../send-mt-sms, multipart/related, a JSON root referring to the RP-DATA by Content-ID)
// and answers 200 with report as the binary part of a multipart/related SmsDeliveryData.
func smsfAnswering(t *testing.T, report []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/ue-contexts/imsi-001/send-mt-sms") {
			t.Errorf("path %s", r.URL.Path)
		}
		mt, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mt != "multipart/related" || params["type"] != "application/json" {
			t.Errorf("Content-Type %q", r.Header.Get("Content-Type"))
		}
		mr := multipart.NewReader(r.Body, params["boundary"])
		root, err := mr.NextPart()
		if err != nil {
			t.Fatalf("root part: %v", err)
		}
		rootBody, _ := io.ReadAll(root)
		if root.Header.Get("Content-Type") != "application/json" || string(rootBody) != `{"smsPayload":{"contentId":"sms"}}` {
			t.Errorf("root part %q: %s", root.Header.Get("Content-Type"), rootBody)
		}
		bin, err := mr.NextPart()
		if err != nil {
			t.Fatalf("binary part: %v", err)
		}
		binBody, _ := io.ReadAll(bin)
		if bin.Header.Get("Content-Type") != "application/vnd.3gpp.sms" || bin.Header.Get("Content-Id") != "sms" ||
			!bytes.Equal(binBody, testRPData) {
			t.Errorf("binary part %q %q: %x", bin.Header.Get("Content-Type"), bin.Header.Get("Content-Id"), binBody)
		}

		var out bytes.Buffer
		mw := multipart.NewWriter(&out)
		jp, _ := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {"application/json"}})
		_, _ = jp.Write([]byte(`{"smsPayload":{"contentId":"report"}}`))
		if report != nil {
			bp, _ := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {"application/vnd.3gpp.sms"}, "Content-Id": {"report"}})
			_, _ = bp.Write(report)
		}
		_ = mw.Close()
		w.Header().Set("Content-Type", "multipart/related; boundary="+mw.Boundary()+`; type="application/json"`)
		_, _ = w.Write(out.Bytes())
	}
}

// The SMS reaches the SMSF as MtForwardSm with the RP-DATA unchanged; the mobile station's
// RP-ACK (MTI 010) makes it delivered, and the report reaches OTA.
func TestSmsf_MtForwardSm_Delivered(t *testing.T) {
	ack := []byte{0x02, 0x07}
	ev := sendThroughSmsf(t, smsfAnswering(t, ack), rpDataMessage)
	if ev.Status != "DELIVERED" || ev.Cause != "RP_ACK" || ev.TransactionID != "tx-abc" || ev.Bearer != "SBI" {
		t.Errorf("event %+v, want DELIVERED/RP_ACK tx-abc SBI", ev)
	}
	if ev.BearerMeta["deliveryReport"] != base64.StdEncoding.EncodeToString(ack) {
		t.Errorf("deliveryReport %q", ev.BearerMeta["deliveryReport"])
	}
}

// RP-ERROR (MTI 100) from the mobile station fails the SMS with its cause: #22, memory
// capacity exceeded (TS 24.011 Table 8.4).
func TestSmsf_MtForwardSm_RPError(t *testing.T) {
	ev := sendThroughSmsf(t, smsfAnswering(t, []byte{0x04, 0x07, 0x01, 0x16}), rpDataMessage)
	if ev.Status != "FAILED" || ev.Cause != "RP_CAUSE_22" {
		t.Errorf("event %+v, want FAILED/RP_CAUSE_22", ev)
	}
}

// A 200 without a report does not tell the gateway the SMS arrived.
func TestSmsf_MtForwardSm_NoReport(t *testing.T) {
	ev := sendThroughSmsf(t, smsfAnswering(t, nil), rpDataMessage)
	if ev.Status != "FAILED" || ev.Cause != "INVALID_DELIVERY_REPORT" {
		t.Errorf("event %+v, want FAILED/INVALID_DELIVERY_REPORT", ev)
	}
}

// A payload that is not an RP-DATA towards the UE — a bare TPDU, as 0.2.x took — fails
// without reaching the SMSF.
func TestSmsf_PayloadNotRPData(t *testing.T) {
	for name, payload := range map[string]SS7PayloadView{
		"bare TPDU":              {Encoding: "BINARY", Content: "BAoLDA=="},
		"RP-DATA towards the SC": {Encoding: sbiclient.EncodingRPData, Content: base64.StdEncoding.EncodeToString([]byte{0x00, 0x07})},
		"not base64":             {Encoding: sbiclient.EncodingRPData, Content: "%%%"},
	} {
		t.Run(name, func(t *testing.T) {
			called := false
			ev := sendThroughSmsf(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }),
				func(smsfURL string) []byte {
					body, _ := json.Marshal(SbiOtaMessage{
						Header:  SbiHeader{Service: "Nsmsf_SMService", Operation: "MtForwardSm"},
						Routing: SbiRouting{Supi: "imsi-001", SmsfFqdn: smsfURL},
						Payload: payload,
					})
					return body
				})
			if ev.Status != "FAILED" || ev.Cause != "PAYLOAD_NOT_RP_DATA" || called {
				t.Errorf("event %+v, SMSF called %v", ev, called)
			}
		})
	}
}

// An SMSF that keeps failing transiently gets otaMaxDeliver attempts. OTA sees PENDING for
// each but the last, then FAILED RETRIES_EXHAUSTED with the transient cause, and the work
// queue no longer holds the SMS.
func TestSmsf_RetriesExhausted(t *testing.T) {
	srv, conn := runOtaServer(t)
	defer srv.Shutdown()
	defer conn.Close()
	setupOtaStream(t, conn)

	var calls atomic.Int32
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer httpServer.Close()

	amf := sbi.NewAmfClient()
	amf.Client.Transport = http.DefaultTransport
	out, _ := outbound.New(outbound.ProfileSBIDirect, amf)
	c := &Client{conn: conn}
	js, _ := c.JetStream()
	sub := NewOTASubscriber(conn, js, quietLogger(), OTAConfig{Resolver: uecm.NewEmpty(), Outbound: out})
	sub.nakDelay = 10 * time.Millisecond
	if err := sub.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Stop(context.Background()) }()

	deliveries := make(chan DeliveryEvent, otaMaxDeliver+1)
	_, _ = conn.Subscribe(subjectDeliveryEvent, func(msg *gnats.Msg) {
		var ev DeliveryEvent
		_ = json.Unmarshal(msg.Data, &ev)
		deliveries <- ev
	})
	if _, err := js.Publish(context.Background(), subjectSmsfRequest, rpDataMessage(httpServer.URL)); err != nil {
		t.Fatal(err)
	}

	for i := 1; i <= otaMaxDeliver; i++ {
		select {
		case ev := <-deliveries:
			if i < otaMaxDeliver && (ev.Status != "PENDING" || ev.Cause != "HTTP_503") {
				t.Errorf("event %d: %+v, want PENDING/HTTP_503", i, ev)
			}
			if i == otaMaxDeliver && (ev.Status != "FAILED" || ev.Cause != "RETRIES_EXHAUSTED" ||
				ev.BearerMeta["lastCause"] != "HTTP_503" || ev.TransactionID != "tx-abc") {
				t.Errorf("last event: %+v, want FAILED/RETRIES_EXHAUSTED, lastCause HTTP_503", ev)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("event %d not published", i)
		}
	}
	select {
	case ev := <-deliveries:
		t.Errorf("event after the last delivery: %+v", ev)
	case <-time.After(300 * time.Millisecond):
	}
	if n := calls.Load(); n != otaMaxDeliver {
		t.Errorf("SMSF called %d times, want %d", n, otaMaxDeliver)
	}
	stream, err := js.Stream(context.Background(), otaStreamName)
	if err != nil {
		t.Fatal(err)
	}
	info, err := stream.Info(context.Background(), jetstream.WithSubjectFilter(subjectSmsfRequest))
	if err != nil {
		t.Fatal(err)
	}
	if n := info.State.Subjects[subjectSmsfRequest]; n != 0 {
		t.Errorf("work queue still holds %d SMS", n)
	}
}

func TestSmsf_4xxFromSmsf_FailsPermanently(t *testing.T) {
	srv, conn := runOtaServer(t)
	defer srv.Shutdown()
	defer conn.Close()
	setupOtaStream(t, conn)

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer httpServer.Close()

	amf := sbi.NewAmfClient()
	amf.Client.Transport = http.DefaultTransport
	out, _ := outbound.New(outbound.ProfileSBIDirect, amf)

	c := &Client{conn: conn}
	js, _ := c.JetStream()

	sub := NewOTASubscriber(conn, js, quietLogger(), OTAConfig{
		Resolver: uecm.NewEmpty(),
		Outbound: out,
	})
	_ = sub.Start(context.Background())
	defer func() { _ = sub.Stop(context.Background()) }()

	deliveries := make(chan DeliveryEvent, 1)
	_, _ = conn.Subscribe(subjectDeliveryEvent, func(msg *gnats.Msg) {
		var ev DeliveryEvent
		_ = json.Unmarshal(msg.Data, &ev)
		deliveries <- ev
	})

	body, _ := json.Marshal(SbiOtaMessage{
		Header:  SbiHeader{Service: "Nsmsf_SMService", Operation: "SendSMS", Version: "v1"},
		Routing: SbiRouting{Supi: "imsi-001", SmsfFqdn: httpServer.URL},
		Payload: SS7PayloadView{Encoding: sbiclient.EncodingRPData, Content: base64.StdEncoding.EncodeToString(testRPData)},
	})
	_, _ = js.Publish(context.Background(), subjectSmsfRequest, body)

	select {
	case ev := <-deliveries:
		if ev.Status != "FAILED" {
			t.Errorf("status = %q, want FAILED (4xx is permanent)", ev.Status)
		}
		if ev.Cause != "HTTP_400" {
			t.Errorf("cause = %q", ev.Cause)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no delivery event")
	}
}

func TestSmsf_PeeringPending_FailsPermanently(t *testing.T) {
	srv, conn := runOtaServer(t)
	defer srv.Shutdown()
	defer conn.Close()
	setupOtaStream(t, conn)

	mtcIwf, _ := outbound.New(outbound.ProfileMtcIwfRest, nil)

	c := &Client{conn: conn}
	js, _ := c.JetStream()

	sub := NewOTASubscriber(conn, js, quietLogger(), OTAConfig{
		Resolver: uecm.NewEmpty(),
		Outbound: mtcIwf,
	})
	_ = sub.Start(context.Background())
	defer func() { _ = sub.Stop(context.Background()) }()

	deliveries := make(chan DeliveryEvent, 1)
	_, _ = conn.Subscribe(subjectDeliveryEvent, func(msg *gnats.Msg) {
		var ev DeliveryEvent
		_ = json.Unmarshal(msg.Data, &ev)
		deliveries <- ev
	})

	body, _ := json.Marshal(SbiOtaMessage{
		Header:  SbiHeader{Service: "Nsmsf_SMService", Operation: "SendSMS", Version: "v1"},
		Routing: SbiRouting{Supi: "imsi-001", SmsfFqdn: "doesnotmatter"},
		Payload: SS7PayloadView{Encoding: sbiclient.EncodingRPData, Content: base64.StdEncoding.EncodeToString(testRPData)},
	})
	_, _ = js.Publish(context.Background(), subjectSmsfRequest, body)

	select {
	case ev := <-deliveries:
		if ev.Status != "FAILED" || ev.Cause != "PEERING_PENDING" {
			t.Errorf("got status=%q cause=%q, want FAILED/PEERING_PENDING", ev.Status, ev.Cause)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no delivery event")
	}
}

// --- helpers --------------------------------------------------------------

// metricsResultFor table — verifies the bounded-cardinality mapping the
// dispatcher relies on so a code change can't quietly multiply label values.
func TestMetricsResultFor(t *testing.T) {
	cases := []struct{ status, cause, want string }{
		{"DELIVERED", "OK", "delivered"},
		{"DELIVERED", "BYPASSED", "bypassed"},
		{"PENDING", "anything", "pending"},
		{"FAILED", "PEERING_PENDING", "not_implemented"},
		{"FAILED", "INVALID_ROUTING", "client_error"},
		{"FAILED", "UNSUPPORTED_OPERATION", "client_error"},
		{"FAILED", "HTTP_503", "failed"},
		{"FAILED", "RETRIES_EXHAUSTED", "retries_exhausted"},
	}
	for _, c := range cases {
		if got := metricsResultFor(c.status, c.cause); got != c.want {
			t.Errorf("metricsResultFor(%q,%q) = %q, want %q", c.status, c.cause, got, c.want)
		}
	}
}

// txIDFromMetadata table — same-spirit guard against silent contract drift
// (OTA uses tx_id; tolerate the two common alternates).
func TestTxIDFromMetadata(t *testing.T) {
	cases := []struct {
		in   map[string]string
		want string
	}{
		{nil, "unknown"},
		{map[string]string{}, "unknown"},
		{map[string]string{"tx_id": "abc"}, "abc"},
		{map[string]string{"transactionId": "abc"}, "abc"},
		{map[string]string{"transaction_id": "abc"}, "abc"},
		{map[string]string{"tx_id": "", "transactionId": "fallback"}, "fallback"},
	}
	for _, c := range cases {
		if got := txIDFromMetadata(c.in); got != c.want {
			t.Errorf("txIDFromMetadata(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Compile check for the sentinel errors — confirms the dispatcher branches stay
// compiled in even when we refactor.
var _ = errors.Is

// An SMSF that OUTBOUND_ALLOWED_DESTINATIONS does not list is never called: the SMS fails
// permanently, without redelivery.
func TestSmsf_DestinationNotAllowed(t *testing.T) {
	srv, conn := runOtaServer(t)
	defer srv.Shutdown()
	defer conn.Close()
	setupOtaStream(t, conn)

	called := make(chan struct{}, 1)
	smsf := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called <- struct{}{} }))
	defer smsf.Close()

	cfg := sbi.DefaultAmfClientConfig()
	cfg.Destinations, _ = sbi.ParseDestinations("smsf.5gc.example", false)
	amf, err := sbi.NewAmfClientWithConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := outbound.New(outbound.ProfileSBIDirect, amf)
	c := &Client{conn: conn}
	js, _ := c.JetStream()
	sub := NewOTASubscriber(conn, js, quietLogger(), OTAConfig{Resolver: uecm.NewEmpty(), Outbound: out})
	if err := sub.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Stop(context.Background()) }()

	deliveries := make(chan DeliveryEvent, 1)
	_, _ = conn.Subscribe(subjectDeliveryEvent, func(msg *gnats.Msg) {
		var ev DeliveryEvent
		_ = json.Unmarshal(msg.Data, &ev)
		deliveries <- ev
	})
	_, _ = js.Publish(context.Background(), subjectSmsfRequest, rpDataMessage(smsf.URL))
	select {
	case ev := <-deliveries:
		if ev.Status != "FAILED" || ev.Cause != "DESTINATION_NOT_ALLOWED" {
			t.Errorf("event %+v, want FAILED/DESTINATION_NOT_ALLOWED", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no delivery event")
	}
	select {
	case <-called:
		t.Error("the SMSF was called")
	default:
	}
}

// Stop waits for the SMS being sent, which is acknowledged: cut off, it would be sent again
// when JetStream redelivered it.
func TestOTASubscriber_StopWaitsForSMS(t *testing.T) {
	srv, conn := runOtaServer(t)
	defer srv.Shutdown()
	defer conn.Close()
	setupOtaStream(t, conn)

	inSMSF := make(chan struct{})
	finished := make(chan struct{})
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(inSMSF)
		time.Sleep(300 * time.Millisecond)
		close(finished)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer httpServer.Close()

	amf := sbi.NewAmfClient()
	amf.Client.Transport = http.DefaultTransport
	out, _ := outbound.New(outbound.ProfileSBIDirect, amf)
	c := &Client{conn: conn}
	js, _ := c.JetStream()
	sub := NewOTASubscriber(conn, js, quietLogger(), OTAConfig{Resolver: uecm.NewEmpty(), Outbound: out})
	if err := sub.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(context.Background(), subjectSmsfRequest, rpDataMessage(httpServer.URL)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-inSMSF:
	case <-time.After(3 * time.Second):
		t.Fatal("the SMS did not reach the SMSF")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sub.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	select {
	case <-finished:
	default:
		t.Fatal("Stop returned while the SMS was being sent")
	}
	stream, _ := js.Stream(context.Background(), otaStreamName)
	info, err := stream.Info(context.Background(), jetstream.WithSubjectFilter(subjectSmsfRequest))
	if err != nil {
		t.Fatal(err)
	}
	if n := info.State.Subjects[subjectSmsfRequest]; n != 0 {
		t.Errorf("work queue still holds %d SMS: not acknowledged", n)
	}
}
