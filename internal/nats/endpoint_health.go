// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nats

import (
	"net/url"
	"sync"
	"time"
)

const (
	restAfter  = 3            // consecutive transient failures before a network function rests
	restBase   = time.Second  // its first rest; doubled with each further failure
	restCap    = maxRetryWait // the longest rest
	maxTracked = 4096         // network functions remembered at once

	// maxRetryAfter bounds how long a Retry-After is remembered. The value is the peer's: a
	// network function answering Retry-After: 4294967295 would otherwise get no notification
	// until the gateway restarts.
	maxRetryAfter = 5 * time.Minute
)

// endpointHealth remembers, across notifications, each failing network function — the
// scheme://host:port of a callback URI — with its consecutive transient failures and the
// Retry-After it asked for (at most maxRetryAfter). After restAfter failures in a row it rests: the other endpoints
// of a notification are tried instead, for restBase doubling with each further failure, up
// to restCap. A Retry-After is kept to: no request before it. A success forgets the network
// function, so only failing ones are kept, at most maxTracked.
type endpointHealth struct {
	mu        sync.Mutex
	endpoints map[string]*endpointState
}

type endpointState struct {
	failures  int
	restUntil time.Time
	notBefore time.Time // Retry-After
}

// endpointKey names the network function behind uri, for health and for logs: callback URIs
// carry subscriber identities in their paths.
func endpointKey(uri string) string {
	u, err := url.Parse(uri)
	if err != nil || u.Host == "" {
		return "(invalid URI)"
	}
	return u.Scheme + "://" + u.Host
}

// state reports whether uri's network function rests, and how long its Retry-After still
// forbids calling it.
func (h *endpointHealth) state(uri string, now time.Time) (resting bool, wait time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.endpoints[endpointKey(uri)]
	if st == nil {
		return false, 0
	}
	return now.Before(st.restUntil), max(st.notBefore.Sub(now), 0)
}

// anyHealthy reports whether an endpoint not dropped neither rests nor waits.
func (h *endpointHealth) anyHealthy(endpoints []string, dropped []bool, now time.Time) bool {
	for i, uri := range endpoints {
		if resting, wait := h.state(uri, now); !dropped[i] && !resting && wait == 0 {
			return true
		}
	}
	return false
}

// earliestCall is how long until an endpoint not dropped may be called: 0 when one may now.
func (h *endpointHealth) earliestCall(endpoints []string, dropped []bool, now time.Time) time.Duration {
	earliest := time.Duration(-1)
	for i, uri := range endpoints {
		if dropped[i] {
			continue
		}
		if _, wait := h.state(uri, now); earliest < 0 || wait < earliest {
			earliest = wait
		}
	}
	return max(earliest, 0)
}

// failed records a transient failure of uri's network function, with the Retry-After it
// answered (0 without one).
func (h *endpointHealth) failed(uri string, retryAfter time.Duration, now time.Time) {
	key := endpointKey(uri)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.endpoints == nil {
		h.endpoints = map[string]*endpointState{}
	}
	st := h.endpoints[key]
	if st == nil {
		if len(h.endpoints) >= maxTracked {
			h.sweep(now)
		}
		if len(h.endpoints) >= maxTracked {
			return
		}
		st = &endpointState{}
		h.endpoints[key] = st
	}
	st.failures++
	if st.failures >= restAfter {
		st.restUntil = now.Add(min(restBase<<min(st.failures-restAfter, 10), restCap))
	}
	if until := now.Add(min(retryAfter, maxRetryAfter)); retryAfter > 0 && until.After(st.notBefore) {
		st.notBefore = until
	}
}

// succeeded forgets uri's network function.
func (h *endpointHealth) succeeded(uri string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.endpoints, endpointKey(uri))
}

// sweep forgets the network functions that neither rest nor wait. Called with mu held.
func (h *endpointHealth) sweep(now time.Time) {
	for key, st := range h.endpoints {
		if !now.Before(st.restUntil) && !now.Before(st.notBefore) {
			delete(h.endpoints, key)
		}
	}
}
