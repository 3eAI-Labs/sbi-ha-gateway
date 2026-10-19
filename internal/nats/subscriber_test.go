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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers/outbound"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/sbi"
	natsserver "github.com/nats-io/nats-server/v2/server"
	gnats "github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
)

// fakeOutbound lets each test script per-endpoint behaviour without spinning
// up real HTTP servers. Calls are recorded so the failover order can be
// asserted instead of inferred.
type fakeOutbound struct {
	mu         sync.Mutex
	calls      []string
	respond    func(uri string) (*outbound.Response, error)
	respondCtx func(ctx context.Context, uri string) (*outbound.Response, error) // instead of respond
	prof       outbound.Profile
}

func (f *fakeOutbound) Profile() outbound.Profile {
	if f.prof == "" {
		return outbound.ProfileSBIDirect
	}
	return f.prof
}

func (f *fakeOutbound) Send(ctx context.Context, req *outbound.Request) (*outbound.Response, error) {
	f.mu.Lock()
	f.calls = append(f.calls, req.CallbackURI)
	f.mu.Unlock()
	if f.respondCtx != nil {
		return f.respondCtx(ctx, req.CallbackURI)
	}
	return f.respond(req.CallbackURI)
}

func (f *fakeOutbound) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

func newQuietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func runQuickServer() *natsserver.Server {
	s, _ := natsserver.NewServer(&natsserver.Options{Port: -1})
	go s.Start()
	if !s.ReadyForConnections(5 * time.Second) {
		panic("nats not ready")
	}
	return s
}

func TestNotificationPayload_endpoints_DedupesAndOrders(t *testing.T) {
	p := NotificationPayload{
		CallbackUri:           "http://amf-1/cb",
		AlternateCallbackUris: []string{"http://amf-2/cb", "", "http://amf-1/cb", "http://amf-3/cb"},
	}
	got := deliveryEndpoints(p)
	want := []string{"http://amf-1/cb", "http://amf-2/cb", "http://amf-3/cb"}
	assert.Equal(t, want, got, "must keep order, drop empties, drop duplicates")
}

func TestDeliverWithFailover_PrimarySucceeds(t *testing.T) {
	fake := &fakeOutbound{
		respond: func(uri string) (*outbound.Response, error) {
			return &outbound.Response{StatusCode: 200}, nil
		},
	}
	s := &Subscriber{outbound: fake, log: newQuietLogger(), callbackTimeout: 100 * time.Millisecond}
	result := s.deliverWithFailover(context.Background(), []string{"http://primary"}, nil).result
	assert.Equal(t, "ok", result)
	assert.Equal(t, []string{"http://primary"}, fake.Calls())
}

func TestDeliverWithFailover_FailsOverToAlternate(t *testing.T) {
	fake := &fakeOutbound{
		respond: func(uri string) (*outbound.Response, error) {
			if uri == "http://primary" {
				return nil, errors.New("connection refused")
			}
			return &outbound.Response{StatusCode: 200}, nil
		},
	}
	s := &Subscriber{outbound: fake, log: newQuietLogger(), callbackTimeout: 100 * time.Millisecond}
	result := s.deliverWithFailover(context.Background(), []string{"http://primary", "http://alt"}, nil).result

	assert.Equal(t, "failover", result, "delivering via alternate must surface as 'failover'")
	assert.Equal(t, []string{"http://primary", "http://alt"}, fake.Calls(),
		"primary must be tried first then alternate; no extra calls")
}

func TestDeliverWithFailover_4xxAborts(t *testing.T) {
	fake := &fakeOutbound{
		respond: func(uri string) (*outbound.Response, error) {
			return &outbound.Response{StatusCode: 403, Body: []byte(`{"cause":"FORBIDDEN"}`)},
				&sbi.HTTPError{StatusCode: 403, Body: []byte(`{"cause":"FORBIDDEN"}`)}
		},
	}
	s := &Subscriber{outbound: fake, log: newQuietLogger(), callbackTimeout: 100 * time.Millisecond}
	result := s.deliverWithFailover(context.Background(), []string{"http://primary", "http://alt"}, nil).result

	assert.Equal(t, "client_error", result)
	assert.Equal(t, []string{"http://primary"}, fake.Calls(),
		"4xx on primary MUST NOT failover to alternate — caller bug, would loop")
}

func TestDeliverWithFailover_AllExhausted(t *testing.T) {
	// All endpoints return 5xx: one call per pass for the sole endpoint, the
	// default number of passes.
	var calls atomic.Int32
	fake := &fakeOutbound{
		respond: func(uri string) (*outbound.Response, error) {
			calls.Add(1)
			return &outbound.Response{StatusCode: 503},
				&sbi.HTTPError{StatusCode: 503}
		},
	}
	s := &Subscriber{outbound: fake, log: newQuietLogger(), callbackTimeout: 50 * time.Millisecond}
	s.WithRetry(0, 10*time.Millisecond)
	result := s.deliverWithFailover(context.Background(), []string{"http://only"}, nil).result

	assert.Equal(t, "exhausted", result)
	assert.Equal(t, int32(DefaultFailoverPasses), calls.Load(),
		"each pass must attempt the (sole) endpoint exactly once")
}

// MAX_RETRIES and RETRY_BASE_DELAY: the number of passes and the backoff between them,
// doubling.
func TestDeliverWithFailover_RetryPolicy(t *testing.T) {
	var calls atomic.Int32
	fake := &fakeOutbound{
		respond: func(uri string) (*outbound.Response, error) {
			calls.Add(1)
			return &outbound.Response{StatusCode: 503}, &sbi.HTTPError{StatusCode: 503}
		},
	}
	s := &Subscriber{outbound: fake, log: newQuietLogger(), callbackTimeout: 50 * time.Millisecond}
	s.WithRetry(4, 20*time.Millisecond)
	start := time.Now()
	result := s.deliverWithFailover(context.Background(), []string{"http://a", "http://b"}, nil).result
	elapsed := time.Since(start)

	assert.Equal(t, "exhausted", result)
	assert.Equal(t, int32(8), calls.Load(), "4 passes over 2 endpoints")
	assert.GreaterOrEqual(t, elapsed, 140*time.Millisecond, "backoff 20+40+80 ms")
	assert.Less(t, elapsed, time.Second)
}

func TestDeliverWithFailover_BypassedIsSuccess(t *testing.T) {
	fake := &fakeOutbound{
		prof: outbound.ProfileSCEFRest,
		respond: func(uri string) (*outbound.Response, error) {
			return nil, outbound.ErrBypassed
		},
	}
	s := &Subscriber{outbound: fake, log: newQuietLogger(), callbackTimeout: 100 * time.Millisecond}
	result := s.deliverWithFailover(context.Background(), []string{"http://primary", "http://alt"}, nil).result

	assert.Equal(t, "bypassed", result)
	assert.Equal(t, []string{"http://primary"}, fake.Calls(),
		"bypass on first endpoint must short-circuit; alternates not tried")
}

// End-to-end: a real NATS message reaches the alternate when the primary answers 503.
func TestSubscriber_HandleE2E_PrimaryFailsAlternateWins(t *testing.T) {
	srv := runQuickServer()
	defer srv.Shutdown()

	conn, err := gnats.Connect(srv.ClientURL())
	assert.NoError(t, err)
	defer conn.Close()

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer primary.Close()
	got := make(chan string, 1)
	alt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- string(body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer alt.Close()

	amf := sbi.NewAmfClient()
	amf.Client.Transport = http.DefaultTransport
	out, _ := outbound.New(outbound.ProfileSBIDirect, amf)

	sub := NewSubscriberWithOutbound(conn, newQuietLogger(), out, 200*time.Millisecond)
	assert.NoError(t, sub.Start())
	defer func() { _ = sub.Stop(context.Background()) }()

	payload, _ := json.Marshal(NotificationPayload{
		CallbackUri:           primary.URL,
		AlternateCallbackUris: []string{alt.URL},
		ChangeItem:            json.RawMessage(`{"hello":"world"}`),
	})
	assert.NoError(t, conn.Publish("5g.data.notify", payload))
	select {
	case body := <-got:
		assert.JSONEq(t, `{"hello":"world"}`, body)
	case <-time.After(3 * time.Second):
		t.Fatal("the alternate got no notification")
	}
}
