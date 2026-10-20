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
	// Outcome is "success", "rejected" (the request was refused: 4xx, OAuth) or "failed"
	// (it could not be carried out: 5xx, an undelivered notification).
	Outcome string `json:"outcome,omitempty"`
	// Status is the HTTP status the requester got; Cause the error's cause (ProblemDetails
	// cause, rejection reason).
	Status int    `json:"status,omitempty"`
	Cause  string `json:"cause,omitempty"`
	// RequestID correlates the event with the access log line.
	RequestID string `json:"request_id,omitempty"`
	// Target is the peer an action addressed: the network function (scheme://host:port).
	Target string `json:"target,omitempty"`
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
		doneCh    chan struct{} // closed when the worker has emptied the queue and exited
		dropCount uint64        // atomic — incremented on queue overflow
		failCount uint64        // atomic — incremented when the publisher refuses an event
	}
)

// stopWait bounds how long SetPublisher(nil) waits for the worker to publish the queue.
const stopWait = 5 * time.Second

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
		// Tear down: stop the worker and wait, up to stopWait, while it publishes the events
		// still queued: the caller closes the connection next.
		if state.stopCh != nil {
			close(state.stopCh)
			select {
			case <-state.doneCh:
			case <-time.After(stopWait):
			}
			state.stopCh, state.doneCh = nil, nil
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
	state.doneCh = make(chan struct{})
	go runWorker(state.queue, state.stopCh, state.doneCh, p, state.subject)
}

// Drops returns the number of audit events that overflowed the queue
// since startup. Surface in /metrics so operators can size queueSize / NATS.
func Drops() uint64 {
	return atomic.LoadUint64(&state.dropCount)
}

// PublishFailures returns the number of audit events the publisher refused since startup;
// each was logged instead, with all its fields.
func PublishFailures() uint64 {
	return atomic.LoadUint64(&state.failCount)
}

// Log records an audit event. Non-blocking when a publisher is configured:
// enqueues into the worker channel; on overflow it falls back to slog and
// increments the drop counter. Without a publisher it slogs synchronously.
func Log(ctx context.Context, userID, action, resource, resourceID string, payload interface{}) {
	Emit(ctx, Event{
		UserID:     userID,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Payload:    payload,
	})
}

// Emit records ev as Log does; its Timestamp is set here.
func Emit(ctx context.Context, ev Event) {
	ev.Timestamp = time.Now().UTC()

	state.RLock()
	queue := state.queue
	state.RUnlock()

	if queue == nil {
		// No publisher configured — slog fallback.
		logEvent(ctx, slog.LevelInfo, "AUDIT_EVENT", ev)
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
		logEvent(ctx, slog.LevelWarn, "AUDIT_EVENT_DROPPED", ev)
	}
}

// logEvent writes ev, every field, to the log: the trail when NATS cannot take it.
func logEvent(ctx context.Context, level slog.Level, msg string, ev Event, extra ...any) {
	slog.Log(ctx, level, msg, append([]any{
		"user_id", ev.UserID,
		"action", ev.Action,
		"resource", ev.Resource,
		"resource_id", ev.ResourceID,
		"outcome", ev.Outcome,
		"status", ev.Status,
		"cause", ev.Cause,
		"request_id", ev.RequestID,
		"target", ev.Target,
		"payload", ev.Payload,
		"timestamp", ev.Timestamp,
	}, extra...)...)
}

// runWorker drains the queue and publishes each event. When stopCh closes it publishes what
// is still queued — the connection is closed only after SetPublisher(nil) returns — and closes
// done.
func runWorker(queue chan Event, stopCh, done chan struct{}, p Publisher, subject string) {
	defer close(done)
	for {
		select {
		case ev := <-queue:
			publishOrFallback(p, subject, ev)
		case <-stopCh:
			for {
				select {
				case ev := <-queue:
					publishOrFallback(p, subject, ev)
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
		// Publisher failed (NATS down etc.): the event goes to the log, whole, so that it
		// still reaches operations, and is counted.
		atomic.AddUint64(&state.failCount, 1)
		logEvent(context.Background(), slog.LevelWarn, "AUDIT_EVENT_PUBLISH_FAILED", ev, "subject", subject, "error", err)
		return
	}
}
