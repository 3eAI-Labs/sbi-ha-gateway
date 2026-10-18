// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package audit

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakePublisher records every Publish call. Safe for concurrent use.
type fakePublisher struct {
	mu       sync.Mutex
	messages []recorded
	err      error // when non-nil, all Publishes return this
}

type recorded struct {
	subject string
	data    []byte
}

func (p *fakePublisher) Publish(subject string, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	p.messages = append(p.messages, recorded{subject: subject, data: append([]byte(nil), data...)})
	return nil
}

func (p *fakePublisher) snapshot() []recorded {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]recorded, len(p.messages))
	copy(out, p.messages)
	return out
}

// resetAuditState ensures one test's publisher doesn't bleed into the next.
// SetPublisher(nil, "") tears down the worker and clears state.
func resetAuditState(t *testing.T) {
	t.Helper()
	SetPublisher(nil, "")
	atomic.StoreUint64(&state.dropCount, 0)
}

func TestLog_NoPublisher_FallsBackToSlog(t *testing.T) {
	resetAuditState(t)
	// No SetPublisher call — slog path. Just verify no panic and no drop.
	Log(context.Background(), "amf-1", "REGISTER", "uecm", "imsi-286***", nil)
	if Drops() != 0 {
		t.Errorf("no-publisher path must not increment Drops; got %d", Drops())
	}
}

func TestLog_WithPublisher_PublishesEvent(t *testing.T) {
	resetAuditState(t)
	pub := &fakePublisher{}
	SetPublisher(pub, "")
	t.Cleanup(func() { resetAuditState(t) })

	Log(context.Background(), "amf-1", "REGISTER", "uecm", "imsi-286***", map[string]string{"foo": "bar"})

	// Worker is async — wait for the publish.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(pub.snapshot()) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	msgs := pub.snapshot()
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	if msgs[0].subject != DefaultSubject {
		t.Errorf("subject = %q, want %q", msgs[0].subject, DefaultSubject)
	}
	var ev Event
	if err := json.Unmarshal(msgs[0].data, &ev); err != nil {
		t.Fatalf("json: %v", err)
	}
	if ev.UserID != "amf-1" || ev.Action != "REGISTER" || ev.Resource != "uecm" {
		t.Errorf("event fields wrong: %+v", ev)
	}
	if ev.Timestamp.IsZero() {
		t.Error("timestamp not set")
	}
}

func TestLog_CustomSubject(t *testing.T) {
	resetAuditState(t)
	pub := &fakePublisher{}
	SetPublisher(pub, "tenant-x.audit.events")
	t.Cleanup(func() { resetAuditState(t) })

	Log(context.Background(), "u", "A", "r", "rid", nil)
	time.Sleep(50 * time.Millisecond)

	msgs := pub.snapshot()
	if len(msgs) != 1 || msgs[0].subject != "tenant-x.audit.events" {
		t.Errorf("custom subject not honoured: %+v", msgs)
	}
}

func TestLog_PublisherFailure_StaysAlive(t *testing.T) {
	resetAuditState(t)
	pub := &fakePublisher{err: errors.New("nats down")}
	SetPublisher(pub, "")
	t.Cleanup(func() { resetAuditState(t) })

	// Several events; worker must NOT die on publish failure.
	for i := 0; i < 5; i++ {
		Log(context.Background(), "u", "A", "r", "rid", nil)
	}
	time.Sleep(50 * time.Millisecond)

	// Recover: clear the error and verify a new event publishes.
	pub.mu.Lock()
	pub.err = nil
	pub.mu.Unlock()
	Log(context.Background(), "u", "RECOVERED", "r", "rid", nil)

	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		msgs := pub.snapshot()
		if len(msgs) > 0 {
			return // worker survived
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("worker stopped publishing after error")
}

// TestLog_QueueOverflow_DropsAndCounts saturates the queue without letting
// the worker drain by giving the publisher a long-blocking Publish.
func TestLog_QueueOverflow_DropsAndCounts(t *testing.T) {
	resetAuditState(t)
	block := make(chan struct{})
	pub := &blockingPublisher{block: block}
	SetPublisher(pub, "")
	t.Cleanup(func() {
		close(block)
		resetAuditState(t)
	})

	// Pump (queueSize + 200) events. The first one goes to the worker
	// (which blocks on Publish); the next queueSize fill the channel; the
	// remainder must be dropped without blocking the caller.
	const overflow = 200
	for i := 0; i < queueSize+overflow+1; i++ {
		Log(context.Background(), "u", "A", "r", "rid", nil)
	}

	got := Drops()
	// Allow some slack — the channel may absorb 1 extra (the worker pulled
	// one and is blocked on Publish, freeing a slot). Anywhere in [overflow-2, overflow+2].
	if got < overflow-2 || got > overflow+2 {
		t.Errorf("Drops = %d, want ~%d", got, overflow)
	}
}

type blockingPublisher struct{ block chan struct{} }

func (b *blockingPublisher) Publish(string, []byte) error {
	<-b.block
	return nil
}

func TestSetPublisher_ToNil_TearsDown(t *testing.T) {
	resetAuditState(t)
	pub := &fakePublisher{}
	SetPublisher(pub, "")

	Log(context.Background(), "u", "A", "r", "rid", nil)
	time.Sleep(50 * time.Millisecond)
	if len(pub.snapshot()) != 1 {
		t.Fatal("publisher path didn't run before teardown")
	}

	SetPublisher(nil, "") // teardown
	// After teardown, Log must NOT publish anymore (slog fallback).
	Log(context.Background(), "u", "A", "r", "rid", nil)
	time.Sleep(50 * time.Millisecond)
	if len(pub.snapshot()) != 1 {
		t.Errorf("publisher received message after SetPublisher(nil): %+v", pub.snapshot())
	}
}

func TestSetPublisher_RepeatedCall_DoesNotSpawnSecondWorker(t *testing.T) {
	resetAuditState(t)
	pub1 := &fakePublisher{}
	SetPublisher(pub1, "")
	pub2 := &fakePublisher{} // attempted swap — should be rejected
	SetPublisher(pub2, "")
	t.Cleanup(func() { resetAuditState(t) })

	Log(context.Background(), "u", "A", "r", "rid", nil)
	time.Sleep(50 * time.Millisecond)

	// pub1 (the first publisher) keeps receiving; pub2 stays empty. Avoids
	// the race of two workers draining one channel.
	if len(pub1.snapshot()) != 1 {
		t.Errorf("first publisher should still own the worker; got %d msgs", len(pub1.snapshot()))
	}
	if len(pub2.snapshot()) != 0 {
		t.Errorf("second publisher should NOT have received messages; got %d", len(pub2.snapshot()))
	}
}

// Backwards-compat sanity: the old (pre-Sprint-C4) call site shape still
// compiles and runs without a publisher. Existing callers shouldn't notice.
func TestLog_BackwardsCompatibleAPI(t *testing.T) {
	resetAuditState(t)
	Log(context.Background(), "user", "ACTION", "resource", "rid", "any payload")
	// No assertion — passing if no panic + no compilation error.
}
