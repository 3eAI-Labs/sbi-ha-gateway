// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nats

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"sync"
	"time"

	sbiclient "github.com/3eAI-Labs/sbi-ha-gateway-client"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers/outbound"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/sbi"
	"github.com/nats-io/nats.go"
)

// DefaultCallbackTimeout is the default timeout for callback delivery
const DefaultCallbackTimeout = 5 * time.Second

// DefaultFailoverPasses is the number of whole-list passes before giving up
// (MAX_RETRIES). Within a pass we try every endpoint exactly once; between
// passes we apply exponential backoff. Three passes against a list of 2
// endpoints is 6 calls — enough to ride out a brief brown-out without holding
// the NATS message indefinitely.
const DefaultFailoverPasses = 3

// DefaultRetryBaseDelay is the backoff after the first failed pass
// (RETRY_BASE_DELAY); it doubles after each further one.
const DefaultRetryBaseDelay = time.Second

// DefaultNotifyWorkers is how many notifications one gateway delivers at once
// (NOTIFY_WORKERS): a notification whose network function does not answer holds one worker,
// not the notifications behind it.
const DefaultNotifyWorkers = 32

// maxRetryWait is the longest wait before another pass that a Retry-After can impose. Asked
// to wait longer, the gateway gives up rather than hold the notification in a worker.
const maxRetryWait = 30 * time.Second

type Subscriber struct {
	conn            *nats.Conn
	log             *slog.Logger
	outbound        outbound.Client
	sub             *nats.Subscription
	callbackTimeout time.Duration
	passes          int
	baseDelay       time.Duration
	workers         int
	health          endpointHealth

	slots    chan struct{} // a token per busy worker
	mu       sync.Mutex
	stopped  bool // set by Stop: no new deliveries start
	inflight sync.WaitGroup
	ctx      context.Context // cancelled when Stop runs out of time
	cancel   context.CancelFunc
}

// NewSubscriber creates a subscriber with default outbound client (sbi_direct
// profile, default AmfClient).
func NewSubscriber(conn *nats.Conn, log *slog.Logger) *Subscriber {
	c, _ := outbound.New(outbound.ProfileSBIDirect, sbi.NewAmfClient())
	return NewSubscriberWithConfig(conn, log, c, DefaultCallbackTimeout)
}

// NewSubscriberWithClient creates a subscriber with a custom AmfClient under
// the default sbi_direct profile. Kept for compatibility with existing tests.
func NewSubscriberWithClient(conn *nats.Conn, log *slog.Logger, amfClient *sbi.AmfClient) *Subscriber {
	c, _ := outbound.New(outbound.ProfileSBIDirect, amfClient)
	return NewSubscriberWithConfig(conn, log, c, DefaultCallbackTimeout)
}

// NewSubscriberWithOutbound injects a fully-built outbound.Client. This is the
// path main.go uses once OUTBOUND_PROFILE is parsed; tests can use it to plug
// in a fake outbound.Client directly.
func NewSubscriberWithOutbound(conn *nats.Conn, log *slog.Logger, c outbound.Client, callbackTimeout time.Duration) *Subscriber {
	return NewSubscriberWithConfig(conn, log, c, callbackTimeout)
}

// NewSubscriberWithConfig creates a subscriber with full configuration control.
func NewSubscriberWithConfig(conn *nats.Conn, log *slog.Logger, c outbound.Client, callbackTimeout time.Duration) *Subscriber {
	if callbackTimeout == 0 {
		callbackTimeout = DefaultCallbackTimeout
	}
	return &Subscriber{
		conn:            conn,
		log:             log,
		outbound:        c,
		callbackTimeout: callbackTimeout,
	}
}

// WithRetry sets the number of passes over the callback URIs and the backoff after
// the first failed pass, which doubles after each further one. Values below 1 pass or
// 0 delay mean the defaults.
func (s *Subscriber) WithRetry(passes int, baseDelay time.Duration) *Subscriber {
	s.passes, s.baseDelay = passes, baseDelay
	return s
}

// WithWorkers sets how many notifications are delivered at once; below 1 means
// DefaultNotifyWorkers.
func (s *Subscriber) WithWorkers(n int) *Subscriber {
	s.workers = n
	return s
}

func (s *Subscriber) retryPolicy() (passes int, baseDelay time.Duration) {
	passes, baseDelay = s.passes, s.baseDelay
	if passes < 1 {
		passes = DefaultFailoverPasses
	}
	if baseDelay <= 0 {
		baseDelay = DefaultRetryBaseDelay
	}
	return passes, baseDelay
}

// NotificationPayload is the message on sbiclient.SubjectDataNotify.
type NotificationPayload = sbiclient.NotificationPayload

// endpoints returns the ordered delivery list: primary first, alternates next,
// duplicates and empties stripped. Returning a []string instead of indexing
// keeps the failover loop free of off-by-ones.
func deliveryEndpoints(p NotificationPayload) []string {
	out := make([]string, 0, 1+len(p.AlternateCallbackUris))
	seen := map[string]struct{}{}
	add := func(uri string) {
		if uri == "" {
			return
		}
		if _, dup := seen[uri]; dup {
			return
		}
		seen[uri] = struct{}{}
		out = append(out, uri)
	}
	add(p.CallbackUri)
	for _, alt := range p.AlternateCallbackUris {
		add(alt)
	}
	return out
}

func (s *Subscriber) Start() error {
	workers := s.workers
	if workers < 1 {
		workers = DefaultNotifyWorkers
	}
	s.slots = make(chan struct{}, workers)
	s.ctx, s.cancel = context.WithCancel(context.Background())

	// Subscribe to data change notifications from the back end.
	// Queue Group "sbi-gateway" ensures only ONE instance processes the event
	// (load-shared across replicas, not broadcast).
	sub, err := s.conn.QueueSubscribe(sbiclient.SubjectDataNotify, "sbi-gateway", s.handle)
	if err != nil {
		return err
	}
	s.sub = sub
	return nil
}

// handle gives one notification to a worker. With every worker busy it waits, and NATS
// keeps the notifications arriving meanwhile in the subscription's pending buffer.
// Notifications are delivered concurrently, so their order is not kept — nor was it across
// replicas.
func (s *Subscriber) handle(msg *nats.Msg) {
	s.slots <- struct{}{}
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		<-s.slots
		s.log.Error("Notification arrived after shutdown began; not delivered")
		return
	}
	s.inflight.Add(1)
	s.mu.Unlock()
	go func() {
		defer func() {
			<-s.slots
			s.inflight.Done()
		}()
		s.process(msg.Data)
	}()
}

// process delivers one notification and, when no network function got it, tells the back
// end on SubjectDataNotifyFailed. Bypassed profiles (scef_rest) count as delivered: another
// adapter delivers.
func (s *Subscriber) process(data []byte) {
	var payload NotificationPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		s.log.Error("Failed to unmarshal notification", slog.Any("error", err))
		return
	}
	endpoints := deliveryEndpoints(payload)
	if len(endpoints) == 0 {
		s.log.Error("Notification has no callback URIs")
		return
	}

	profile := string(s.outbound.Profile())
	out := s.deliverWithFailover(s.ctx, endpoints, payload.ChangeItem)
	metrics.RecordOutboundDelivery(profile, out.result)
	switch out.result {
	case "ok", "failover", "bypassed":
		return
	}
	s.log.Error("Notification not delivered",
		slog.String("result", out.result),
		slog.String("cause", out.cause),
		slog.Int("attempts", out.attempts),
		slog.Int("endpoints", len(endpoints)),
		slog.String("primary", endpointKey(endpoints[0])),
	)
	s.publishFailure(payload, out)
}

func (s *Subscriber) publishFailure(payload NotificationPayload, out notifyOutcome) {
	failure := sbiclient.NotificationFailure{
		Notification: payload,
		Result:       out.result,
		Status:       out.status,
		Cause:        out.cause,
		Attempts:     out.attempts,
	}
	if body := bytes.TrimSpace(out.body); len(body) > 0 && body[0] == '{' && json.Valid(body) {
		failure.ProblemDetails = body
	}
	data, err := json.Marshal(failure)
	if err == nil {
		err = s.conn.Publish(sbiclient.SubjectDataNotifyFailed, data)
	}
	if err != nil {
		s.log.Error("Failed to publish the notification failure", slog.Any("error", err))
	}
}

// withoutURI is err for a log line: a *url.Error names the whole callback URI, subscriber
// identity included, so only what it wraps is kept; an HTTP error is its status, its body
// being the network function's.
func withoutURI(err error) error {
	var httpErr *sbi.HTTPError
	if errors.As(err, &httpErr) {
		return fmt.Errorf("HTTP %d", httpErr.StatusCode)
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}

// notifyOutcome is how one notification's delivery ended.
type notifyOutcome struct {
	result   string // metric label; sbiclient.Notify* when not delivered
	attempts int
	status   int    // last HTTP status
	body     []byte // and its body
	cause    string
}

// deliverWithFailover runs the failover policy:
//   - Pass = one ordered traversal of [primary, ...alternates].
//   - Within a pass each endpoint gets at most one attempt. An endpoint whose network
//     function failed repeatedly rests (endpointHealth) and is skipped while another
//     endpoint is available; when all rest, all are tried. An endpoint inside a Retry-After
//     is not called.
//   - 4xx response on any endpoint aborts the entire delivery: it is the
//     caller's bug, retrying or failing-over would loop indefinitely.
//   - An endpoint OUTBOUND_ALLOWED_DESTINATIONS refuses is dropped; an unimplemented
//     profile ends the delivery.
//   - 5xx / 429 / transport error advances to the next endpoint immediately.
//   - After a pass without delivery, exponential backoff (base delay, then doubled: 1s, 2s
//     with the defaults), longer when Retry-After asks for it, and a new pass — up to the
//     configured number of passes. A Retry-After beyond maxRetryWait ends the delivery.
//   - ctx cancelled (Stop out of time) ends it too.
func (s *Subscriber) deliverWithFailover(ctx context.Context, endpoints []string, changeItem interface{}) notifyOutcome {
	passes, baseDelay := s.retryPolicy()
	var out notifyOutcome
	dropped := make([]bool, len(endpoints)) // refused by OUTBOUND_ALLOWED_DESTINATIONS
passes:
	for pass := 0; pass < passes; pass++ {
		now := time.Now()
		preferHealthy := s.health.anyHealthy(endpoints, dropped, now)
		for idx, uri := range endpoints {
			if dropped[idx] {
				continue
			}
			resting, wait := s.health.state(uri, now)
			if wait > 0 {
				metrics.RecordOutboundEndpointSkip("retry_after")
				if out.attempts == 0 {
					out.cause = "RETRY_AFTER"
				}
				continue
			}
			if resting && preferHealthy {
				metrics.RecordOutboundEndpointSkip("resting")
				continue
			}

			out.attempts++
			attemptCtx, cancel := context.WithTimeout(ctx, s.callbackTimeout)
			_, err := s.outbound.Send(attemptCtx, &outbound.Request{
				CallbackURI: uri,
				Payload:     changeItem,
			})
			cancel()

			var httpErr *sbi.HTTPError
			switch {
			case err == nil:
				s.health.succeeded(uri)
				metrics.RecordOutboundPosition(idx)
				s.log.Debug("Callback delivered",
					slog.String("endpoint", endpointKey(uri)),
					slog.Int("position", idx),
					slog.Int("pass", pass),
				)
				// Leaving the primary or its first try is a failover, not a clean OK.
				out.result = "ok"
				if pass > 0 || idx > 0 {
					out.result = "failover"
				}
				return out
			case errors.Is(err, outbound.ErrBypassed):
				s.log.Debug("Outbound profile bypassed; another adapter delivers",
					slog.String("profile", string(s.outbound.Profile())))
				out.result = "bypassed"
				return out
			case errors.Is(err, outbound.ErrMtcIwfNotImplemented), errors.Is(err, outbound.ErrScefNotImplemented):
				out.result, out.cause = sbiclient.NotifyNotImplemented, "PEERING_PENDING"
				return out
			case errors.Is(err, sbi.ErrDestinationNotAllowed):
				dropped[idx] = true
				out.cause = "DESTINATION_NOT_ALLOWED"
				s.log.Warn("Callback URI not allowed by OUTBOUND_ALLOWED_DESTINATIONS",
					slog.String("endpoint", endpointKey(uri)))
				continue
			case errors.As(err, &httpErr):
				out.status, out.body, out.cause = httpErr.StatusCode, httpErr.Body, fmt.Sprintf("HTTP_%d", httpErr.StatusCode)
				if !httpErr.IsRetryable() {
					s.log.Warn("Callback rejected with non-retryable status; giving up",
						slog.String("endpoint", endpointKey(uri)),
						slog.Int("status", httpErr.StatusCode),
					)
					out.result = sbiclient.NotifyClientError
					return out
				}
				s.health.failed(uri, httpErr.RetryAfter, time.Now())
			case ctx.Err() != nil:
				out.cause = "SHUTDOWN"
				break passes
			default:
				out.cause = "TRANSPORT_ERROR"
				s.health.failed(uri, 0, time.Now())
			}
			s.log.Warn("Endpoint delivery failed; trying next",
				slog.String("endpoint", endpointKey(uri)),
				slog.Int("position", idx),
				slog.Int("pass", pass),
				slog.String("cause", out.cause),
				slog.Any("error", withoutURI(err)),
			)
		}

		if !slices.Contains(dropped, false) {
			out.result = sbiclient.NotifyNotAllowed
			return out
		}
		if pass == passes-1 {
			break
		}
		wait := baseDelay << pass
		if until := s.health.earliestCall(endpoints, dropped, time.Now()); until > wait {
			wait = until
		}
		if wait > maxRetryWait {
			out.cause = "RETRY_AFTER_TOO_LONG"
			break
		}
		s.log.Debug("No endpoint delivered; backing off before retry",
			slog.Duration("backoff", wait),
			slog.Int("next_pass", pass+1),
		)
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			out.cause = "SHUTDOWN"
			break passes
		}
	}
	out.result = sbiclient.NotifyExhausted
	return out
}

// Stop drains the subscription and waits, until ctx ends, for the notifications it handed
// to workers. Deliveries still running then are cancelled; each reports its failure.
func (s *Subscriber) Stop(ctx context.Context) error {
	if s.sub == nil {
		return nil
	}
	s.log.Info("Draining NATS subscription...")
	closed := s.sub.StatusChanged(nats.SubscriptionClosed)
	err := s.sub.Drain()
	if err == nil {
		// Drain hands the pending notifications to handle, then closes the subscription.
		select {
		case <-closed:
		case <-ctx.Done():
		}
	}
	s.mu.Lock()
	s.stopped = true
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		s.inflight.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		s.log.Warn("Shutdown deadline: cancelling notification deliveries still running")
		s.cancel()
		<-done
		if err == nil {
			err = ctx.Err()
		}
	}
	s.cancel()
	if err != nil {
		s.log.Error("Notification subscriber did not stop cleanly", slog.Any("error", err))
		return err
	}
	s.log.Info("NATS subscription drained; every notification delivered or reported")
	return nil
}
