// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nats

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func TestBuildSmsfSendURI(t *testing.T) {
	cases := []struct {
		fqdn, supi, want string
	}{
		{"smsf-1.5gc.tr", "imsi-286010000000001",
			"https://smsf-1.5gc.tr/nsmsf-sms/v2/ue-contexts/imsi-286010000000001/sendsms"},
		// Already-schemed FQDN must NOT be double-prefixed.
		{"http://smsf-1.5gc.tr:8080", "imsi-001",
			"http://smsf-1.5gc.tr:8080/nsmsf-sms/v2/ue-contexts/imsi-001/sendsms"},
		// Trailing slash on FQDN trimmed; SUPI escaped.
		{"https://smsf-1.5gc.tr/", "suci-0-001-01-0-0-0-12345",
			"https://smsf-1.5gc.tr/nsmsf-sms/v2/ue-contexts/suci-0-001-01-0-0-0-12345/sendsms"},
	}
	for _, c := range cases {
		if got := buildSmsfSendURI(c.fqdn, c.supi); got != c.want {
			t.Errorf("buildSmsfSendURI(%q, %q) = %q, want %q", c.fqdn, c.supi, got, c.want)
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
	defer func() { _ = sub.Stop() }()

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
	defer func() { _ = sub.Stop() }()

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
	defer func() { _ = sub.Stop() }()

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
	defer func() { _ = sub.Stop() }()

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

func TestSmsf_HappyPath_PostsToSmsfAndPublishesDelivery(t *testing.T) {
	srv, conn := runOtaServer(t)
	defer srv.Shutdown()
	defer conn.Close()
	setupOtaStream(t, conn)

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated) // SMSF returns 201 on accept
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
	if err := sub.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Stop() }()

	// Collect delivery events.
	deliveries := make(chan DeliveryEvent, 4)
	_, err := conn.Subscribe(subjectDeliveryEvent, func(msg *gnats.Msg) {
		var ev DeliveryEvent
		_ = json.Unmarshal(msg.Data, &ev)
		deliveries <- ev
	})
	if err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(SbiOtaMessage{
		Header:   SbiHeader{Service: "Nsmsf_SMService", Operation: "SendSMS", Version: "v1"},
		Routing:  SbiRouting{Supi: "imsi-001", SmsfFqdn: httpServer.URL},
		Payload:  SS7PayloadView{Encoding: "BINARY", Content: "ZHVtbXk="},
		Metadata: map[string]string{"tx_id": "tx-abc"},
	})
	if _, err := js.Publish(context.Background(), subjectSmsfRequest, body); err != nil {
		t.Fatalf("publish: %v", err)
	}

	select {
	case ev := <-deliveries:
		if ev.Status != "DELIVERED" {
			t.Errorf("status = %q, want DELIVERED", ev.Status)
		}
		if ev.TransactionID != "tx-abc" {
			t.Errorf("tx_id = %q", ev.TransactionID)
		}
		if ev.Bearer != "SBI" {
			t.Errorf("bearer = %q, want SBI", ev.Bearer)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no delivery event published within 3s")
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
	defer func() { _ = sub.Stop() }()

	deliveries := make(chan DeliveryEvent, 1)
	_, _ = conn.Subscribe(subjectDeliveryEvent, func(msg *gnats.Msg) {
		var ev DeliveryEvent
		_ = json.Unmarshal(msg.Data, &ev)
		deliveries <- ev
	})

	body, _ := json.Marshal(SbiOtaMessage{
		Header:  SbiHeader{Service: "Nsmsf_SMService", Operation: "SendSMS", Version: "v1"},
		Routing: SbiRouting{Supi: "imsi-001", SmsfFqdn: httpServer.URL},
		Payload: SS7PayloadView{Encoding: "BINARY", Content: "ZA=="},
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
	defer func() { _ = sub.Stop() }()

	deliveries := make(chan DeliveryEvent, 1)
	_, _ = conn.Subscribe(subjectDeliveryEvent, func(msg *gnats.Msg) {
		var ev DeliveryEvent
		_ = json.Unmarshal(msg.Data, &ev)
		deliveries <- ev
	})

	body, _ := json.Marshal(SbiOtaMessage{
		Header:  SbiHeader{Service: "Nsmsf_SMService", Operation: "SendSMS", Version: "v1"},
		Routing: SbiRouting{Supi: "imsi-001", SmsfFqdn: "doesnotmatter"},
		Payload: SS7PayloadView{Encoding: "BINARY", Content: "ZA=="},
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
