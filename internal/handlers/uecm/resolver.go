// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

// Package uecm resolves an MSISDN to its 5G Nudm_UECM context (SUPI + SMSF
// registration) for the serving-SMSF lookup on sbi.outbound.nudm.uecm.request.
//
// This package deliberately does NOT contain a real UDM client today —
// real UDM integration requires NRF discovery + Nudm_SDM_Get +
// Nudm_UECM_Get and is not implemented. The Resolver interface keeps
// the call site (internal/nats OTA subscriber) decoupled from that future
// work. The default implementation is file-backed (or empty), so an
// operator with no UDM yet can still boot the gateway and let the SMS
// platform fall back to its Diameter / MAP probe.
package uecm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

// ErrNotFound is the canonical "no UE context for this MSISDN" sentinel.
// The OTA UECM handler maps this to ProblemDetails cause=NF_NOT_FOUND with
// HTTP status 404 in the reply envelope, which lets the SMS platform fall
// back to Diameter S6c / MAP SRI at once instead of waiting for a timeout.
var ErrNotFound = errors.New("uecm: no UE context for MSISDN")

// Context is the projection the Nudm_UECM RESPONSE envelope needs.
// Field names mirror NudmUecmMessage so the handler can copy them across
// without an intermediate mapping layer.
type Context struct {
	Supi       string
	SmsfFqdn   string
	SmsfPlmnId string
}

// Resolver looks up a 5G UECM context by MSISDN. Implementations must be
// safe for concurrent use. A non-nil error other than ErrNotFound is treated
// as a transient failure and surfaces as HTTP 503 in the reply — OTA will
// retry / fall back accordingly.
type Resolver interface {
	Resolve(ctx context.Context, msisdn string) (*Context, error)
}

// emptyResolver is the carrier-grade default when no resolver source is
// configured: every lookup returns ErrNotFound. OTA's probe budget expires
// and the request graceful-fails over to the Diameter / MAP probe paths,
// which is the intended behaviour while no UDM is wired.
//
// This is NOT a stub for testing — it is the production default until the
// real UDM client lands. Operators who need deterministic SBI lookups for
// a fixed catalogue (lab, soak test) point OTA_RESOLVER_FILE at a JSON map.
type emptyResolver struct{}

// NewEmpty returns a Resolver that always returns ErrNotFound.
func NewEmpty() Resolver { return emptyResolver{} }

func (emptyResolver) Resolve(_ context.Context, _ string) (*Context, error) {
	return nil, ErrNotFound
}

// fileResolver loads a JSON map { "MSISDN": {Supi, SmsfFqdn, SmsfPlmnId} }
// at construction time. Lookup is in-memory; the file is read once. To
// rotate the catalogue, restart the process (5G NF deployments rotate via
// rolling restart anyway — fsnotify here would be premature).
type fileResolver struct {
	mu      sync.RWMutex
	entries map[string]Context
}

// NewFromFile loads a JSON file mapping MSISDN → Context. Empty path
// returns NewEmpty() so OTA_RESOLVER_FILE="" is a valid "no catalogue"
// configuration. A path that exists but cannot be parsed is fatal —
// silently degrading to empty would mask an operator typo.
func NewFromFile(path string) (Resolver, error) {
	if path == "" {
		return NewEmpty(), nil
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- OTA_RESOLVER_FILE, set by the operator, never by a request
	if err != nil {
		return nil, fmt.Errorf("uecm: read resolver file %q: %w", path, err)
	}
	var entries map[string]Context
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("uecm: parse resolver file %q: %w", path, err)
	}
	// Reject obviously-broken entries up front: an entry without Supi or
	// SmsfFqdn cannot satisfy a Nudm_UECM RESPONSE — better to fail at
	// startup than to reply with a malformed envelope at probe time.
	for msisdn, c := range entries {
		if c.Supi == "" || c.SmsfFqdn == "" {
			return nil, fmt.Errorf("uecm: entry for %q missing Supi or SmsfFqdn", msisdn)
		}
	}
	return &fileResolver{entries: entries}, nil
}

func (r *fileResolver) Resolve(_ context.Context, msisdn string) (*Context, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.entries[msisdn]
	if !ok {
		return nil, ErrNotFound
	}
	// Defensive copy: callers must not mutate the catalogue through the
	// returned pointer.
	out := c
	return &out, nil
}
