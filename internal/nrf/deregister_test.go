// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nrf

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func registeredProfile(t *testing.T, nrf *fakeNRF, c *Client) Profile {
	t.Helper()
	p := testProfile(t)
	_, err := c.Register(context.Background(), p)
	require.NoError(t, err)
	return p
}

// No pod heartbeats any more: deleted, then a delete a heartbeat interval later finds nothing.
func TestDeregister_Quiet(t *testing.T) {
	nrf := newFakeNRF(t)
	c := nrf.start(t)
	p := registeredProfile(t, nrf, c)
	s := &script{steps: []func(){nil}}
	err := (&Deregisterer{Client: c, Profiles: []Profile{p}, Log: discard, sleep: s.sleep}).Run(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"PUT", "GET", "DELETE", "DELETE"}, nrf.callLog())
	assert.Equal(t, []time.Duration{10*time.Second + quietMargin}, s.waits, "the NRF's heartbeat interval, read back")
	assert.False(t, nrf.registered(p.InstanceID))
}

// A pod still stopping heartbeats, is answered 404 and registers again: deleted again, and
// done only once a whole interval passes without it.
func TestDeregister_PodRegistersAgain(t *testing.T) {
	nrf := newFakeNRF(t)
	c := nrf.start(t)
	p := registeredProfile(t, nrf, c)
	s := &script{steps: []func(){
		func() { _, _ = c.Register(context.Background(), p) }, // the stopping pod
		nil,
	}}
	err := (&Deregisterer{Client: c, Profiles: []Profile{p}, Log: discard, sleep: s.sleep}).Run(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"PUT", "GET", "DELETE", "PUT", "DELETE", "DELETE"}, nrf.callLog())
	assert.False(t, nrf.registered(p.InstanceID))
}

// Nothing registered (already removed, or never): still outwaits one interval.
func TestDeregister_NotRegistered(t *testing.T) {
	nrf := newFakeNRF(t)
	c := nrf.start(t)
	p := testProfile(t)
	p.Heartbeat = 7 * time.Second
	s := &script{steps: []func(){nil}}
	err := (&Deregisterer{Client: c, Profiles: []Profile{p}, Log: discard, sleep: s.sleep}).Run(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"GET", "DELETE", "DELETE"}, nrf.callLog())
	assert.Equal(t, []time.Duration{7*time.Second + quietMargin}, s.waits, "the proposal when the NRF has no profile")
}

func TestDeregister_NRFRefuses(t *testing.T) {
	nrf := newFakeNRF(t)
	c := nrf.start(t)
	p := registeredProfile(t, nrf, c)
	nrf.set(func(f *fakeNRF) { f.fail = http.StatusForbidden })
	err := (&Deregisterer{Client: c, Profiles: []Profile{p}, Log: discard, sleep: (&script{}).sleep}).Run(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 403")
	assert.Contains(t, err.Error(), p.InstanceID)
}

func TestDeregister_TimeRunsOut(t *testing.T) {
	nrf := newFakeNRF(t)
	c := nrf.start(t)
	p := registeredProfile(t, nrf, c)
	s := &script{} // the context ends at the first wait
	err := (&Deregisterer{Client: c, Profiles: []Profile{p}, Log: discard, sleep: s.sleep}).Run(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "time ran out")
}
