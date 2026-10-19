// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nats

import (
	"fmt"
	"testing"
	"time"
)

// A network function rests after restAfter failures in a row, longer with each further one
// up to restCap; a success forgets it.
func TestEndpointHealth_Rest(t *testing.T) {
	var h endpointHealth
	now := time.Now()
	const uri = "https://smsf.example:443/cb/imsi-001"
	for i := 1; i < restAfter; i++ {
		h.failed(uri, 0, now)
	}
	if resting, _ := h.state(uri, now); resting {
		t.Fatalf("resting after %d failures", restAfter-1)
	}
	for i, want := range []time.Duration{restBase, 2 * restBase, 4 * restBase} {
		h.failed(uri, 0, now)
		if resting, _ := h.state(uri, now.Add(want-time.Millisecond)); !resting {
			t.Errorf("failure %d: not resting before %s", restAfter+i, want)
		}
		if resting, _ := h.state(uri, now.Add(want)); resting {
			t.Errorf("failure %d: still resting at %s", restAfter+i, want)
		}
	}
	for range 40 {
		h.failed(uri, 0, now)
	}
	if resting, _ := h.state(uri, now.Add(restCap)); resting {
		t.Errorf("rest beyond restCap %s", restCap)
	}
	h.succeeded("https://smsf.example:443/other")
	if resting, _ := h.state(uri, now); resting {
		t.Error("still resting after a success on the same network function")
	}
}

// Only failing network functions are kept, and no more than maxTracked: under that limit the
// ones that neither rest nor wait are forgotten first.
func TestEndpointHealth_Bounded(t *testing.T) {
	var h endpointHealth
	now := time.Now()
	for i := range maxTracked {
		h.failed(fmt.Sprintf("http://nf-%d", i), time.Minute, now)
	}
	h.failed("http://nf-new", time.Minute, now)
	if _, wait := h.state("http://nf-new", now); wait != 0 {
		t.Error("tracked beyond maxTracked while every other one still waits")
	}
	later := now.Add(2 * time.Minute)
	h.failed("http://nf-later", time.Minute, later)
	if _, wait := h.state("http://nf-later", later); wait != time.Minute {
		t.Error("not tracked although the others no longer wait")
	}
	if len(h.endpoints) != 1 {
		t.Errorf("%d network functions kept, want 1", len(h.endpoints))
	}
}

// A Retry-After is remembered for maxRetryAfter at most: the peer cannot shut its network
// function off from notifications until the gateway restarts.
func TestEndpointHealth_RetryAfterBounded(t *testing.T) {
	var h endpointHealth
	now := time.Now()
	h.failed("http://nf", 1<<32*time.Second, now)
	if _, wait := h.state("http://nf", now); wait != maxRetryAfter {
		t.Errorf("Retry-After remembered for %s, want %s", wait, maxRetryAfter)
	}
	if _, wait := h.state("http://nf", now.Add(maxRetryAfter)); wait != 0 {
		t.Error("still waiting after maxRetryAfter")
	}
}
