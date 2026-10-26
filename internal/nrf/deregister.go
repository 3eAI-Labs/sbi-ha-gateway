// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nrf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// quietMargin is added to the heartbeat interval when waiting for a pod that may still
// heartbeat: a heartbeat answered 404 is followed by a registration at once, and either
// request may take a while. The gateway's choice.
const quietMargin = 10 * time.Second

// Deregisterer removes the profiles from the NRF when the installation is removed (the
// chart's post-delete hook runs it: sbi-gateway nrf-deregister).
//
// The installation's pods may still be stopping, and one that heartbeats in between is
// answered 404 and registers the instance again. So each profile is deleted, and deleted
// again after a heartbeat interval, until a delete finds nothing: no pod heartbeated it for
// a whole interval, and a stopping pod never starts again. ctx bounds the whole.
type Deregisterer struct {
	Client   *Client
	Profiles []Profile
	Log      *slog.Logger

	sleep func(ctx context.Context, d time.Duration) bool // tests replace it
}

// Run deregisters every profile; the error names each that is not.
func (d *Deregisterer) Run(ctx context.Context) error {
	errs := make([]error, len(d.Profiles))
	var wg sync.WaitGroup
	for i, p := range d.Profiles {
		wg.Go(func() { errs[i] = d.one(ctx, p) })
	}
	wg.Wait()
	return errors.Join(errs...)
}

func (d *Deregisterer) wait(ctx context.Context, t time.Duration) bool {
	if d.sleep != nil {
		return d.sleep(ctx, t)
	}
	timer := time.NewTimer(t)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (d *Deregisterer) one(ctx context.Context, p Profile) error {
	log := d.Log.With(slog.String("nf_type", p.Type), slog.String("nf_instance_id", p.InstanceID))
	// The interval to outwait: the NRF's, read from the registered profile; else the
	// proposed one; else the gateway's fallback.
	interval, _, err := d.Client.Retrieve(ctx, p)
	if err != nil {
		log.Warn("Could not read the heartbeat interval from the NRF", slog.Any("error", err))
	}
	if interval == 0 {
		interval = p.Heartbeat
		if interval == 0 {
			interval = fallbackHeartbeat
		}
	}
	quiet := interval + quietMargin
	for round := 1; ; round++ {
		existed, err := d.Client.Deregister(ctx, p)
		if err != nil {
			return fmt.Errorf("%s %s: %w", p.Type, p.InstanceID, err)
		}
		if !existed && round > 1 {
			log.Info("Deregistered from the NRF", slog.Int("deletes", round))
			return nil
		}
		if existed && round > 1 {
			log.Info("A pod registered the instance again; waiting for it to stop", slog.Duration("wait", quiet))
		}
		if !d.wait(ctx, quiet) {
			return fmt.Errorf("%s %s: still registered when the time ran out: %w", p.Type, p.InstanceID, ctx.Err())
		}
	}
}
