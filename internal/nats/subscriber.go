// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nats

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
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

type Subscriber struct {
	conn            *nats.Conn
	log             *slog.Logger
	outbound        outbound.Client
	sub             *nats.Subscription
	callbackTimeout time.Duration
	passes          int
	baseDelay       time.Duration
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

// handle processes one notification message. Bypassed profiles (scef_rest)
// are treated as success — another adapter is responsible for delivery.
func (s *Subscriber) handle(msg *nats.Msg) {
	var payload NotificationPayload
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		s.log.Error("Failed to unmarshal notification", slog.Any("error", err))
		return
	}

	endpoints := deliveryEndpoints(payload)
	if len(endpoints) == 0 {
		s.log.Error("Notification has no callback URIs", slog.String("subject", msg.Subject))
		return
	}

	profile := string(s.outbound.Profile())
	s.log.Info("Received Data Change Notification",
		slog.String("primary_uri", endpoints[0]),
		slog.Int("alternates", len(endpoints)-1),
		slog.String("profile", profile),
	)

	result := s.deliverWithFailover(endpoints, payload.ChangeItem)
	metrics.RecordOutboundDelivery(profile, result)
}

// deliverWithFailover runs the failover policy:
//   - Pass = one ordered traversal of [primary, ...alternates].
//   - Within a pass each endpoint gets exactly one attempt.
//   - 4xx response on any endpoint aborts the entire delivery: it is the
//     caller's bug, retrying or failing-over would loop indefinitely.
//   - 5xx / 429 / transport error advances to the next endpoint immediately.
//   - After all endpoints fail in a pass, exponential backoff (base delay,
//     then doubled: 1s, 2s, 4s by default) and start a new pass — up to the
//     configured number of passes.
//
// Returns one of the metric `result` enum values.
func (s *Subscriber) deliverWithFailover(endpoints []string, changeItem interface{}) string {
	passes, baseDelay := s.retryPolicy()
	for pass := 0; pass < passes; pass++ {
		for idx, uri := range endpoints {
			ctx, cancel := context.WithTimeout(context.Background(), s.callbackTimeout)
			resp, err := s.outbound.Send(ctx, &outbound.Request{
				CallbackURI: uri,
				Payload:     changeItem,
			})
			cancel()

			if err == nil {
				s.log.Info("Callback delivered",
					slog.String("uri", uri),
					slog.Int("position", idx),
					slog.Int("pass", pass),
				)
				metrics.RecordOutboundPosition(idx)
				if pass > 0 || idx > 0 {
					// We had to leave the primary on its first try —
					// surface this as a failover, not a clean OK.
					return "failover"
				}
				return "ok"
			}

			// Bypassed profile: configured to delegate elsewhere, ack as success.
			if errors.Is(err, outbound.ErrBypassed) {
				s.log.Info("Outbound profile bypassed; another adapter delivers",
					slog.String("profile", string(s.outbound.Profile())))
				return "bypassed"
			}

			// 4xx → caller's fault: do not retry, do not failover.
			var httpErr *sbi.HTTPError
			if errors.As(err, &httpErr) && !httpErr.IsRetryable() {
				s.log.Error("Callback rejected with non-retryable status; giving up",
					slog.String("uri", uri),
					slog.Int("status", httpErr.StatusCode),
					slog.String("body", string(httpErr.Body)),
				)
				_ = resp // *Response may carry status/body; already logged via httpErr
				return "client_error"
			}

			s.log.Warn("Endpoint delivery failed; trying next",
				slog.String("uri", uri),
				slog.Int("position", idx),
				slog.Int("pass", pass),
				slog.Any("error", err),
			)
		}

		// All endpoints failed this pass — back off before retrying.
		if pass < passes-1 {
			backoff := baseDelay << pass
			s.log.Warn("All endpoints failed; backing off before retry",
				slog.Duration("backoff", backoff),
				slog.Int("next_pass", pass+1),
			)
			time.Sleep(backoff)
		}
	}

	s.log.Error("All endpoints exhausted across all passes",
		slog.Int("endpoint_count", len(endpoints)),
		slog.Int("passes", passes),
	)
	return "exhausted"
}

// Stop gracefully drains the subscription and unsubscribes.
// Drain allows in-flight messages to be processed before closing.
func (s *Subscriber) Stop() error {
	if s.sub == nil {
		return nil
	}

	s.log.Info("Draining NATS subscription...")

	// Drain is preferred over Unsubscribe - it processes pending messages
	// before unsubscribing, ensuring no message loss during graceful shutdown
	if err := s.sub.Drain(); err != nil {
		s.log.Error("Failed to drain subscription", slog.Any("error", err))
		return err
	}

	s.log.Info("NATS subscription drained successfully")
	return nil
}
