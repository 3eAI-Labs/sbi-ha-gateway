// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nats

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	sbiclient "github.com/3eAI-Labs/sbi-ha-gateway-client"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers/outbound"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
	cgaudit "github.com/3eAI-Labs/sbi-ha-gateway/internal/platform/audit"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/sbi"
	gnats "github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ok(string) (*outbound.Response, error) { return &outbound.Response{StatusCode: 204}, nil }

func unavailable(retryAfter time.Duration) (*outbound.Response, error) {
	return nil, &sbi.HTTPError{StatusCode: 503, RetryAfter: retryAfter}
}

// startSubscriber runs a Subscriber over fake on an embedded NATS server and returns the
// connection, for publishing notifications, and the failures the gateway reports.
func startSubscriber(t *testing.T, fake *fakeOutbound, workers int) (*gnats.Conn, *Subscriber, <-chan sbiclient.NotificationFailure) {
	t.Helper()
	srv := runQuickServer()
	t.Cleanup(srv.Shutdown)
	conn, err := gnats.Connect(srv.ClientURL())
	require.NoError(t, err)
	t.Cleanup(conn.Close)

	failures := make(chan sbiclient.NotificationFailure, 10)
	_, err = conn.Subscribe(sbiclient.SubjectDataNotifyFailed, func(msg *gnats.Msg) {
		var f sbiclient.NotificationFailure
		_ = json.Unmarshal(msg.Data, &f)
		failures <- f
	})
	require.NoError(t, err)
	require.NoError(t, conn.Flush())

	sub := NewSubscriberWithOutbound(conn, newQuietLogger(), fake, time.Second).
		WithRetry(1, 10*time.Millisecond).WithWorkers(workers)
	require.NoError(t, sub.Start())
	return conn, sub, failures
}

func notify(t *testing.T, conn *gnats.Conn, uris ...string) {
	t.Helper()
	data, _ := json.Marshal(NotificationPayload{CallbackUri: uris[0], AlternateCallbackUris: uris[1:],
		ChangeItem: json.RawMessage(`{"n":1}`)})
	require.NoError(t, conn.Publish(sbiclient.SubjectDataNotify, data))
}

// A network function that does not answer holds one worker: the notifications behind it go
// out meanwhile. 0.2.x delivered one at a time per gateway, so the second waited for every
// attempt on the first (C.5, measured 700 ms there).
func TestSubscriber_NoHeadOfLineBlocking(t *testing.T) {
	release := make(chan struct{})
	delivered := make(chan string, 2)
	fake := &fakeOutbound{respond: func(uri string) (*outbound.Response, error) {
		if uri == "http://stuck" {
			<-release
		}
		delivered <- uri
		return &outbound.Response{StatusCode: 204}, nil
	}}
	conn, sub, _ := startSubscriber(t, fake, 4)
	defer func() { _ = sub.Stop(context.Background()) }()
	defer close(release)

	notify(t, conn, "http://stuck")
	notify(t, conn, "http://fine")
	select {
	case uri := <-delivered:
		assert.Equal(t, "http://fine", uri)
	case <-time.After(2 * time.Second):
		t.Fatal("the second notification waited for the first")
	}
}

// A Retry-After is kept to: the network function is not called again before it, even when
// the backoff is shorter.
func TestDeliverWithFailover_RetryAfter(t *testing.T) {
	var mu sync.Mutex
	var at []time.Time
	fake := &fakeOutbound{respond: func(string) (*outbound.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		at = append(at, time.Now())
		if len(at) == 1 {
			return unavailable(300 * time.Millisecond)
		}
		return &outbound.Response{StatusCode: 204}, nil
	}}
	s := NewSubscriberWithOutbound(nil, newQuietLogger(), fake, time.Second).WithRetry(3, 10*time.Millisecond)

	out := s.deliverWithFailover(context.Background(), []string{"http://nf"}, nil)
	assert.Equal(t, "failover", out.result, "delivered on the second pass")
	require.Len(t, at, 2)
	assert.GreaterOrEqual(t, at[1].Sub(at[0]), 300*time.Millisecond, "called again inside Retry-After")

	// With an alternate still callable the next pass comes after the backoff: it skips the
	// network function inside its Retry-After and calls the alternate only.
	fake = &fakeOutbound{respond: func(uri string) (*outbound.Response, error) {
		if uri == "http://busy" {
			return unavailable(time.Minute)
		}
		return unavailable(0)
	}}
	s = NewSubscriberWithOutbound(nil, newQuietLogger(), fake, time.Second).WithRetry(2, 10*time.Millisecond)
	out = s.deliverWithFailover(context.Background(), []string{"http://busy", "http://alt"}, nil)
	assert.Equal(t, sbiclient.NotifyExhausted, out.result)
	assert.Equal(t, []string{"http://busy", "http://alt", "http://alt"}, fake.Calls())
}

// A Retry-After longer than the gateway holds a notification ends the delivery at once.
func TestDeliverWithFailover_RetryAfterTooLong(t *testing.T) {
	fake := &fakeOutbound{respond: func(string) (*outbound.Response, error) { return unavailable(time.Hour) }}
	s := NewSubscriberWithOutbound(nil, newQuietLogger(), fake, time.Second).WithRetry(3, 10*time.Millisecond)

	start := time.Now()
	out := s.deliverWithFailover(context.Background(), []string{"http://nf"}, nil)
	assert.Equal(t, notifyOutcome{result: sbiclient.NotifyExhausted, attempts: 1, status: 503, cause: "RETRY_AFTER_TOO_LONG"}, out)
	assert.Less(t, time.Since(start), time.Second)

	// The next notification for that network function does not call it either.
	out = s.deliverWithFailover(context.Background(), []string{"http://nf/other"}, nil)
	assert.Equal(t, 0, out.attempts)
	assert.Equal(t, "RETRY_AFTER_TOO_LONG", out.cause)
	assert.Len(t, fake.Calls(), 1)
}

// After restAfter failures in a row a network function rests: the next notification goes to
// its alternate first. When every endpoint rests, all are tried.
func TestDeliverWithFailover_RestingEndpoint(t *testing.T) {
	fake := &fakeOutbound{respond: func(uri string) (*outbound.Response, error) {
		if uri == "http://down:8080/cb" {
			return nil, errors.New("connection refused")
		}
		return &outbound.Response{StatusCode: 204}, nil
	}}
	s := NewSubscriberWithOutbound(nil, newQuietLogger(), fake, time.Second).WithRetry(1, time.Millisecond)

	for range restAfter {
		assert.Equal(t, "failover", s.deliverWithFailover(context.Background(), []string{"http://down:8080/cb", "http://up/cb"}, nil).result)
	}
	before := len(fake.Calls())
	// Another path on the same network function rests too.
	assert.Equal(t, "failover", s.deliverWithFailover(context.Background(), []string{"http://down:8080/other", "http://up/cb"}, nil).result)
	assert.Equal(t, []string{"http://up/cb"}, fake.Calls()[before:], "the resting network function was called")

	before = len(fake.Calls())
	out := s.deliverWithFailover(context.Background(), []string{"http://down:8080/cb"}, nil)
	assert.Equal(t, 1, out.attempts, "with nothing else to try, a resting network function is tried")
	assert.Equal(t, []string{"http://down:8080/cb"}, fake.Calls()[before:])
}

// A profile the operator has not peered yet cannot deliver: one attempt, not every pass.
func TestDeliverWithFailover_NotImplementedEnds(t *testing.T) {
	fake := &fakeOutbound{prof: outbound.ProfileMtcIwfRest, respond: func(string) (*outbound.Response, error) {
		return nil, outbound.ErrMtcIwfNotImplemented
	}}
	s := NewSubscriberWithOutbound(nil, newQuietLogger(), fake, time.Second).WithRetry(3, time.Millisecond)

	out := s.deliverWithFailover(context.Background(), []string{"http://a", "http://b"}, nil)
	assert.Equal(t, sbiclient.NotifyNotImplemented, out.result)
	assert.Equal(t, []string{"http://a"}, fake.Calls())
}

// A callback URI the allowlist refuses is not tried again; the others are. When it refuses
// them all, the delivery ends after one pass.
func TestDeliverWithFailover_DestinationNotAllowed(t *testing.T) {
	fake := &fakeOutbound{respond: func(uri string) (*outbound.Response, error) {
		if uri == "http://a" {
			return nil, sbi.ErrDestinationNotAllowed
		}
		return unavailable(0)
	}}
	s := NewSubscriberWithOutbound(nil, newQuietLogger(), fake, time.Second).WithRetry(2, time.Millisecond)
	out := s.deliverWithFailover(context.Background(), []string{"http://a", "http://b"}, nil)
	assert.Equal(t, sbiclient.NotifyExhausted, out.result)
	assert.Equal(t, []string{"http://a", "http://b", "http://b"}, fake.Calls())

	fake = &fakeOutbound{respond: func(string) (*outbound.Response, error) { return nil, sbi.ErrDestinationNotAllowed }}
	s = NewSubscriberWithOutbound(nil, newQuietLogger(), fake, time.Second).WithRetry(3, time.Millisecond)
	out = s.deliverWithFailover(context.Background(), []string{"http://a", "http://b"}, nil)
	assert.Equal(t, sbiclient.NotifyNotAllowed, out.result)
	assert.Equal(t, []string{"http://a", "http://b"}, fake.Calls())
}

// A notification no network function got is reported to the back end with the network
// function's answer: a 404 says it no longer has the subscription.
func TestSubscriber_ReportsUndeliveredNotification(t *testing.T) {
	fake := &fakeOutbound{respond: func(string) (*outbound.Response, error) {
		return nil, &sbi.HTTPError{StatusCode: 404, Body: []byte(`{"status":404,"cause":"SUBSCRIPTION_NOT_FOUND"}`)}
	}}
	conn, sub, failures := startSubscriber(t, fake, 2)
	defer func() { _ = sub.Stop(context.Background()) }()
	audited := &auditCapture{}
	cgaudit.SetPublisher(audited, "audit.test")
	defer cgaudit.SetPublisher(nil, "")

	notify(t, conn, "http://amf/cb", "http://amf2/cb")
	select {
	case f := <-failures:
		assert.Equal(t, sbiclient.NotifyClientError, f.Result)
		assert.Equal(t, 404, f.Status)
		assert.Equal(t, "HTTP_404", f.Cause)
		assert.Equal(t, 1, f.Attempts)
		assert.JSONEq(t, `{"status":404,"cause":"SUBSCRIPTION_NOT_FOUND"}`, string(f.ProblemDetails))
		assert.Equal(t, "http://amf/cb", f.Notification.CallbackUri)
		assert.Equal(t, []string{"http://amf2/cb"}, f.Notification.AlternateCallbackUris)
		assert.JSONEq(t, `{"n":1}`, string(f.Notification.ChangeItem))
	case <-time.After(2 * time.Second):
		t.Fatal("no NotificationFailure published")
	}
	// The gateway's action for the application is audited too (C.7).
	require.Eventually(t, func() bool { return len(audited.snapshot()) == 1 }, 2*time.Second, 10*time.Millisecond)
	ev := audited.snapshot()[0]
	assert.Equal(t, cgaudit.Event{UserID: "nats", Action: "DeliverNotification", Resource: "notification",
		Outcome: "rejected", Cause: "HTTP_404", Target: "http://amf", Timestamp: ev.Timestamp}, ev)
}

// Stop waits for the deliveries in flight; one still running at the deadline is cancelled and
// reported, not dropped.
func TestSubscriber_StopWaitsThenCancels(t *testing.T) {
	t.Run("waits", func(t *testing.T) {
		delivered := make(chan struct{})
		fake := &fakeOutbound{respond: func(string) (*outbound.Response, error) {
			time.Sleep(300 * time.Millisecond)
			close(delivered)
			return ok("")
		}}
		conn, sub, _ := startSubscriber(t, fake, 2)
		notify(t, conn, "http://slow")
		time.Sleep(50 * time.Millisecond) // the worker has it
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, sub.Stop(ctx))
		select {
		case <-delivered:
		default:
			t.Fatal("Stop returned before the delivery in flight ended")
		}
	})
	t.Run("cancels at the deadline", func(t *testing.T) {
		fake := &fakeOutbound{respondCtx: func(ctx context.Context, _ string) (*outbound.Response, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}}
		conn, sub, failures := startSubscriber(t, fake, 2)
		notify(t, conn, "http://hangs")
		time.Sleep(50 * time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		assert.ErrorIs(t, sub.Stop(ctx), context.DeadlineExceeded)
		select {
		case f := <-failures:
			assert.Equal(t, sbiclient.NotifyExhausted, f.Result)
			assert.Equal(t, "SHUTDOWN", f.Cause)
		case <-time.After(2 * time.Second):
			t.Fatal("the cancelled delivery was not reported")
		}
	})
}

// Callback URIs carry subscriber identities: the failure log names the network function,
// never the URI, also when a transport error would quote it.
func TestDeliverWithFailover_LogsNoCallbackURI(t *testing.T) {
	var logs strings.Builder
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	amf := sbi.NewAmfClient()
	amf.Client.Transport = http.DefaultTransport
	out, _ := outbound.New(outbound.ProfileSBIDirect, amf)
	s := NewSubscriberWithOutbound(nil, log, out, time.Second).WithRetry(1, time.Millisecond)

	s.deliverWithFailover(context.Background(), []string{"http://127.0.0.1:1/nudm-sdm/imsi-001010000000001/sdm-subscriptions"}, nil)
	if strings.Contains(logs.String(), "imsi-") || !strings.Contains(logs.String(), "http://127.0.0.1:1") {
		t.Errorf("log:\n%s", logs.String())
	}
}

type auditCapture struct {
	mu     sync.Mutex
	events []cgaudit.Event
}

func (c *auditCapture) Publish(_ string, data []byte) error {
	var ev cgaudit.Event
	_ = json.Unmarshal(data, &ev)
	c.mu.Lock()
	c.events = append(c.events, ev)
	c.mu.Unlock()
	return nil
}

func (c *auditCapture) snapshot() []cgaudit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]cgaudit.Event(nil), c.events...)
}

func counterOf(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, c.Write(&m))
	return m.GetCounter().GetValue()
}

// callback_retries_total counts each attempt after a failed one, by what failed last (C.8:
// 0.3.0 defined it and never incremented it).
func TestDeliverWithFailover_CountsRetries(t *testing.T) {
	calls := 0
	fake := &fakeOutbound{respond: func(string) (*outbound.Response, error) {
		calls++
		switch calls {
		case 1:
			return unavailable(0)
		case 2:
			return nil, errors.New("connection refused")
		}
		return &outbound.Response{StatusCode: 204}, nil
	}}
	s := NewSubscriberWithOutbound(nil, newQuietLogger(), fake, time.Second).WithRetry(3, time.Millisecond)
	fiveXX := counterOf(t, metrics.CallbackRetries.WithLabelValues("5xx"))
	transport := counterOf(t, metrics.CallbackRetries.WithLabelValues("transport"))

	assert.Equal(t, "failover", s.deliverWithFailover(context.Background(), []string{"http://nf"}, nil).result)
	assert.Equal(t, fiveXX+1, counterOf(t, metrics.CallbackRetries.WithLabelValues("5xx")))
	assert.Equal(t, transport+1, counterOf(t, metrics.CallbackRetries.WithLabelValues("transport")))
}

// A subscription that falls behind loses messages: counted and logged, where nats.go without an
// error handler dropped them unsaid (C.8).
func TestClient_SlowConsumerCounted(t *testing.T) {
	srv := runQuickServer()
	defer srv.Shutdown()
	c, err := NewClientWithSecurity(srv.ClientURL(), newQuietLogger(), time.Second, Security{})
	require.NoError(t, err)
	defer c.Close()
	before := counterOf(t, metrics.NatsEvents.WithLabelValues("slow_consumer"))

	block := make(chan struct{})
	defer close(block)
	sub, err := c.GetConn().Subscribe("slow", func(*gnats.Msg) { <-block })
	require.NoError(t, err)
	require.NoError(t, sub.SetPendingLimits(1, -1))
	for range 20 {
		require.NoError(t, c.GetConn().Publish("slow", []byte("x")))
	}
	require.NoError(t, c.GetConn().Flush())
	require.Eventually(t, func() bool {
		return counterOf(t, metrics.NatsEvents.WithLabelValues("slow_consumer")) > before
	}, 3*time.Second, 20*time.Millisecond)
}
