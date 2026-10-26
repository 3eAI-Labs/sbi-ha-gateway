// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nrf

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
)

// fallbackHeartbeat is the heartbeat interval used when the NRF's registration answer
// carries none, though TS 29.510 Table 6.1.6.2.2-1 says it shall, and none was proposed.
// The gateway's choice, not the specification's.
const fallbackHeartbeat = 60 * time.Second

// Backoff of a failing registration, and of a failing heartbeat up to the heartbeat
// interval: the gateway's choice.
const (
	minBackoff = 1 * time.Second
	maxBackoff = 30 * time.Second
)

// maxRejoin: while the NRF refuses tokens to the instance as an unknown client, the profile
// is registered again on the 1st, 2nd, 4th… refused heartbeat in a row, then on every
// maxRejoin-th: the gateway's choice. The NRF may have dropped the instance, or may know it
// and refuse it for another reason; a registration of a known instance replaces its profile
// (TS 29.510 clause 5.2.2.3.1), which an NRF may notify its subscribers of as a profile
// change (clause 5.2.2.6.2; free5GC's NRF does on every one).
const maxRejoin = 32

// Agent keeps each profile registered from this pod: it registers it, heartbeats it at the
// interval the NRF gives, and registers it again when the NRF answers a heartbeat with 404
// (it lost or dropped the instance), or with 401 and no token for an unknown client.
// Failures are retried; the gateway serves on either way, since its consumers may reach it
// without the NRF.
type Agent struct {
	Client   *Client
	Profiles []Profile
	Log      *slog.Logger

	// sleep waits d or until ctx ends; tests replace it.
	sleep func(ctx context.Context, d time.Duration) bool
}

// Run keeps the profiles registered until ctx ends, then returns. It does not deregister:
// the installation's other pods serve on (see the package documentation).
func (a *Agent) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, p := range a.Profiles {
		wg.Go(func() { a.keep(ctx, p) })
	}
	wg.Wait()
}

func (a *Agent) wait(ctx context.Context, d time.Duration) bool {
	if a.sleep != nil {
		return a.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (a *Agent) keep(ctx context.Context, p Profile) {
	log := a.Log.With(slog.String("nf_type", p.Type), slog.String("nf_instance_id", p.InstanceID))
	metrics.SetNRFRegistered(p.Type, false)
	defer metrics.SetNRFRegistered(p.Type, false)
	backoff := minBackoff
	failing := false          // a failure was logged at WARN; the next ones go to DEBUG until success
	refused, rejoinAt := 0, 1 // heartbeats refused as an unknown client in a row; the count that registers
	report := func(msg string, err error) {
		if !failing {
			log.Warn(msg, slog.Any("error", err))
			failing = true
			return
		}
		log.Debug(msg, slog.Any("error", err))
	}
	for ctx.Err() == nil {
		// Register.
		interval, err := a.Client.Register(ctx, p)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			report("NRF registration failed; retrying", err)
			if !a.wait(ctx, backoff) {
				return
			}
			backoff = min(2*backoff, maxBackoff)
			continue
		}
		if interval == 0 {
			interval = p.Heartbeat
			if interval == 0 {
				interval = fallbackHeartbeat
			}
			log.Warn("The NRF's registration answer carries no heartBeatTimer; heartbeating at a default",
				slog.Duration("interval", interval))
		}
		metrics.SetNRFRegistered(p.Type, true)
		log.Info("Registered with the NRF", slog.Duration("heartbeat", interval))
		failing, backoff = false, minBackoff

		// Heartbeat until the NRF no longer knows the instance.
		next := interval
		for {
			if !a.wait(ctx, next) {
				return
			}
			got, err := a.Client.Heartbeat(ctx, p)
			if IsNotFound(err) {
				metrics.SetNRFRegistered(p.Type, false)
				log.Warn("The NRF does not know the instance; registering it again")
				failing = true
				break
			}
			if unknownClient(err) {
				// The NRF answered 401 and will not issue the instance a token: it may have
				// dropped the instance, its 401 coming before the 404 (free5GC's NRF does
				// so). Registration needs no token.
				if refused++; refused >= rejoinAt {
					refused, rejoinAt = 0, min(2*rejoinAt, maxRejoin)
					metrics.SetNRFRegistered(p.Type, false)
					log.Warn("The NRF refuses the instance an access token as an unknown client; registering it again",
						slog.Any("error", err))
					failing = true
					break
				}
			}
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				// The NRF may still hold the instance: retry soon, within the interval it
				// expects heartbeats at.
				report("NRF heartbeat failed; retrying", err)
				next = min(backoff, interval)
				backoff = min(2*backoff, maxBackoff)
				continue
			}
			if failing {
				log.Info("NRF heartbeat accepted again")
			}
			failing, refused, rejoinAt, backoff = false, 0, 1, minBackoff
			if got > 0 && got != interval {
				log.Info("The NRF changed the heartbeat interval", slog.Duration("heartbeat", got))
				interval = got
			}
			next = interval
		}
	}
}
