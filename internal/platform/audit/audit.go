// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

// Package audit emits compliance-grade audit events for state-changing
// operations. The package is intentionally kept transport-agnostic: it
// accepts an opaque Publisher (typically a NATS connection in production)
// so it has no hard dependency on any messaging client.
//
// Two emit paths exist:
//
//   - When SetPublisher is called, audit.Log enqueues into a bounded
//     channel; a background worker drains it and calls publisher.Publish
//     on the configured subject. Events that overflow the queue are
//     dropped (with a metric and a slog warning) — audit must not become
//     a back-pressure source for the request path.
//
//   - When no publisher is set, audit.Log falls back to slog only. This
//     keeps tests and dev environments running without a NATS dependency.
package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Event represents a significant business action. Field names match the
// JSON wire format on `audit.events`; consumers parse against this shape.
type Event struct {
	UserID     string      `json:"user_id"`
	Action     string      `json:"action"`
	Resource   string      `json:"resource"`
	ResourceID string      `json:"resource_id"`
	Payload    interface{} `json:"payload,omitempty"`
	Timestamp  time.Time   `json:"timestamp"`
}

// Publisher is the minimal contract audit needs from a messaging client.
// nats.Conn satisfies it directly (Publish(subject string, data []byte) error).
type Publisher interface {
	Publish(subject string, data []byte) error
}

// DefaultSubject is where audit events land unless the caller overrides it.
const DefaultSubject = "audit.events"

// queueSize bounds the in-flight audit channel. Carrier-grade default —
// large enough to absorb a 1-second NATS hiccup at 1k events/sec without
// dropping; small enough to bound process memory if NATS stays down.
const queueSize = 1024

var (
	// state is package-global on purpose. audit.Log() is meant to be called
	// from anywhere in the codebase; threading the publisher through every
	// caller would defeat the convenience the package exists for.
	state struct {
		sync.RWMutex
		publisher Publisher
		subject   string
		queue     chan Event
		stopCh    chan struct{}
		dropCount uint64 // atomic — incremented on queue overflow
	}
)

// SetPublisher wires an audit publisher and starts the background worker.
// Calling it a second time is a no-op (the existing worker keeps running).
// Pass nil to disable the publisher path; the slog fallback resumes.
//
// subject="" uses DefaultSubject. Custom subjects are useful for per-tenant
// isolation in shared NATS clusters.
func SetPublisher(p Publisher, subject string) {
	state.Lock()
	defer state.Unlock()

	if p == nil {
		// Tear down: stop the worker, drop the channel ref. Existing in-
		// flight events on the channel are emitted via slog by the worker
		// before it exits.
		if state.stopCh != nil {
			close(state.stopCh)
			state.stopCh = nil
		}
		state.publisher = nil
		state.queue = nil
		return
	}

	if state.publisher != nil {
		// Already running. Update subject only — replacing the publisher
		// at runtime would race in-flight events.
		if subject != "" {
			state.subject = subject
		}
		return
	}

	state.publisher = p
	state.subject = subject
	if state.subject == "" {
		state.subject = DefaultSubject
	}
	state.queue = make(chan Event, queueSize)
	state.stopCh = make(chan struct{})
	go runWorker(state.queue, state.stopCh, p, state.subject)
}

// Drops returns the number of audit events that overflowed the queue
// since startup. Surface in /metrics so operators can size queueSize / NATS.
func Drops() uint64 {
	return atomic.LoadUint64(&state.dropCount)
}

// Log records an audit event. Non-blocking when a publisher is configured:
// enqueues into the worker channel; on overflow it falls back to slog and
// increments the drop counter. Without a publisher it slogs synchronously.
func Log(ctx context.Context, userID, action, resource, resourceID string, payload interface{}) {
	ev := Event{
		UserID:     userID,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Payload:    payload,
		Timestamp:  time.Now().UTC(),
	}

	state.RLock()
	queue := state.queue
	state.RUnlock()

	if queue == nil {
		// No publisher configured — slog fallback.
		slog.InfoContext(ctx, "AUDIT_EVENT",
			"user_id", ev.UserID,
			"action", ev.Action,
			"resource", ev.Resource,
			"resource_id", ev.ResourceID,
			"payload", ev.Payload,
		)
		return
	}

	select {
	case queue <- ev:
		// enqueued; worker will publish
	default:
		// Queue full — overflow path. Drop with telemetry rather than
		// blocking the request handler. Audit availability is best-effort
		// by design (TS 33.501 Annex L); the request must not pay for
		// audit pipeline back-pressure.
		atomic.AddUint64(&state.dropCount, 1)
		slog.WarnContext(ctx, "AUDIT_EVENT_DROPPED",
			"user_id", ev.UserID,
			"action", ev.Action,
			"resource", ev.Resource,
			"resource_id", ev.ResourceID,
		)
	}
}

// runWorker drains the queue and publishes each event. Exits when stopCh
// closes; flushes remaining events to slog before returning so a clean
// shutdown doesn't lose audit events that were already enqueued.
func runWorker(queue chan Event, stopCh chan struct{}, p Publisher, subject string) {
	for {
		select {
		case ev := <-queue:
			publishOrFallback(p, subject, ev)
		case <-stopCh:
			// Drain remaining events to slog (don't try NATS — the operator
			// is shutting it down too).
			for {
				select {
				case ev := <-queue:
					slog.Info("AUDIT_EVENT_DRAINED",
						"user_id", ev.UserID,
						"action", ev.Action,
					)
				default:
					return
				}
			}
		}
	}
}

func publishOrFallback(p Publisher, subject string, ev Event) {
	data, err := json.Marshal(ev)
	if err != nil {
		// Should not happen — Event struct is JSON-clean — but guard so a
		// bad payload from a caller doesn't kill the worker goroutine.
		slog.Error("AUDIT_EVENT_MARSHAL_FAILED",
			"user_id", ev.UserID,
			"action", ev.Action,
			"error", err,
		)
		return
	}
	if err := p.Publish(subject, data); err != nil {
		// Publisher failed (NATS down etc.) — log to slog so the event
		// still reaches operations via the log pipeline.
		slog.Warn("AUDIT_EVENT_PUBLISH_FAILED",
			"user_id", ev.UserID,
			"action", ev.Action,
			"subject", subject,
			"error", err,
		)
		return
	}
}
