// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nrf

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

func gauge(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	m := &dto.Metric{}
	require.NoError(t, g.Write(m))
	return m.GetGauge().GetValue()
}

func testProfile(t *testing.T) Profile {
	t.Helper()
	ps, err := Build([]byte(twoProfiles), Options{TLS: true, OAuth: true}, testAPIs)
	require.NoError(t, err)
	return ps[0]
}

// script is a sleep stub: each wait is recorded, then step i runs (it may change the fake
// NRF); after the last step the wait reports the context ended.
type script struct {
	waits []time.Duration
	steps []func()
}

func (s *script) sleep(_ context.Context, d time.Duration) bool {
	s.waits = append(s.waits, d)
	i := len(s.waits) - 1
	if i >= len(s.steps) {
		return false
	}
	if s.steps[i] != nil {
		s.steps[i]()
	}
	return true
}

func TestAgent_RegistersAndHeartbeats(t *testing.T) {
	nrf := newFakeNRF(t)
	c := nrf.start(t)
	p := testProfile(t)
	s := &script{steps: []func(){
		func() { assert.Equal(t, 1.0, gauge(t, metrics.NRFRegistered.WithLabelValues("UDM"))) },
		nil,
	}}
	a := &Agent{Client: c, Profiles: []Profile{p}, Log: discard, sleep: s.sleep}
	a.Run(context.Background())

	assert.Equal(t, []string{"PUT", "PATCH", "PATCH"}, nrf.callLog())
	assert.Equal(t, []time.Duration{10 * time.Second, 10 * time.Second, 10 * time.Second}, s.waits,
		"heartbeats at the NRF's heartBeatTimer")
	assert.True(t, nrf.registered(p.InstanceID), "a stopping pod does not deregister")
	assert.Equal(t, 0.0, gauge(t, metrics.NRFRegistered.WithLabelValues("UDM")), "this pod no longer holds it")
	for _, proto := range nrf.protos {
		assert.Equal(t, 2, proto, "HTTP/2 (TS 29.500 clause 5.2.1)")
	}
}

// A heartbeat answered 404 (the NRF lost or dropped the instance) registers it again at once.
func TestAgent_RegistersAgainOn404(t *testing.T) {
	nrf := newFakeNRF(t)
	c := nrf.start(t)
	p := testProfile(t)
	s := &script{steps: []func(){
		func() { nrf.set(func(f *fakeNRF) { delete(f.instances, p.InstanceID) }) },
		nil,
	}}
	(&Agent{Client: c, Profiles: []Profile{p}, Log: discard, sleep: s.sleep}).Run(context.Background())

	assert.Equal(t, []string{"PUT", "PATCH", "PUT", "PATCH"}, nrf.callLog())
	assert.True(t, nrf.registered(p.InstanceID))
}

// free5GC's NRF, restarted: it dropped the instance and its tokens, and answers 401 before
// it would 404; a token it issues to registered instances alone. Registering again recovers.
func TestAgent_RegistersAgainOnUnknownClient(t *testing.T) {
	nrf := newFakeNRF(t)
	nrf.oauth = true
	c := nrf.start(t)
	p := testProfile(t)
	s := &script{steps: []func(){
		nil,
		func() { nrf.set(func(f *fakeNRF) { delete(f.instances, p.InstanceID); clear(f.issued) }) },
		nil,
	}}
	(&Agent{Client: c, Profiles: []Profile{p}, Log: discard, sleep: s.sleep}).Run(context.Background())

	// The registration tries a token too (the NRF asked for them) and goes without one.
	assert.Equal(t, []string{"PUT", "PATCH", "TOKEN", "PATCH", "PATCH", "TOKEN", "TOKEN", "PUT", "TOKEN", "PATCH"}, nrf.callLog())
	assert.Equal(t, []time.Duration{10 * time.Second, 10 * time.Second, 10 * time.Second, 10 * time.Second}, s.waits)
	assert.True(t, nrf.registered(p.InstanceID))
}

// An NRF that knows the instance and still refuses it a token (free5GC's, when it lost the
// certificate it signed at registration) is sent the profile on the 1st, 2nd, 4th… refused
// heartbeat in a row; a heartbeat accepted starts the count again.
func TestAgent_UnknownClientBackoff(t *testing.T) {
	nrf := newFakeNRF(t)
	nrf.oauth = true
	refuse := func(f *fakeNRF) { f.tokenFail, f.tokenBody = http.StatusBadRequest, `{"error":"invalid_client"}` }
	refuse(nrf)
	c := nrf.start(t)
	p := testProfile(t)
	steps := make([]func(), 9)
	steps[7] = func() { nrf.set(func(f *fakeNRF) { f.tokenFail = 0 }) }
	steps[8] = func() { nrf.set(func(f *fakeNRF) { refuse(f); clear(f.issued) }) }
	s := &script{steps: steps}
	(&Agent{Client: c, Profiles: []Profile{p}, Log: discard, sleep: s.sleep}).Run(context.Background())

	// The registration tries a token too (the NRF asked for them) and goes without one.
	again := []string{"TOKEN", "PUT"}
	refused := []string{"TOKEN", "PATCH"}
	want := []string{"PUT", "PATCH", "TOKEN"}         // 1st refusal
	want = append(want, again...)                     //   registered again
	want = append(want, refused...)                   // 1st
	want = append(want, refused...)                   // 2nd
	want = append(want, again...)                     //   registered again
	want = append(want, slices.Repeat(refused, 4)...) // 1st to 4th
	want = append(want, again...)                     //   registered again
	want = append(want, "TOKEN", "PATCH")             // accepted
	want = append(want, "PATCH", "TOKEN")             // refused: a new count
	want = append(want, again...)                     //   registered again
	assert.Equal(t, want, nrf.callLog())
	sec := time.Second
	assert.Equal(t, []time.Duration{10 * sec, 10 * sec, 1 * sec, 10 * sec, 1 * sec, 2 * sec, 4 * sec, 10 * sec, 10 * sec, 10 * sec}, s.waits)
}

// A failing NRF is retried with a doubling backoff up to 30 s; the first success resets it.
func TestAgent_RegistrationBackoff(t *testing.T) {
	nrf := newFakeNRF(t)
	nrf.fail = http.StatusServiceUnavailable
	c := nrf.start(t)
	p := testProfile(t)
	steps := make([]func(), 7)
	steps[6] = func() { nrf.set(func(f *fakeNRF) { f.fail = 0 }) }
	s := &script{steps: steps}
	(&Agent{Client: c, Profiles: []Profile{p}, Log: discard, sleep: s.sleep}).Run(context.Background())

	sec := time.Second
	assert.Equal(t, []time.Duration{1 * sec, 2 * sec, 4 * sec, 8 * sec, 16 * sec, 30 * sec, 30 * sec, 10 * sec}, s.waits)
	assert.True(t, nrf.registered(p.InstanceID))
}

// A failing heartbeat is retried sooner than the interval, never later.
func TestAgent_HeartbeatRetry(t *testing.T) {
	nrf := newFakeNRF(t)
	nrf.heartbeat = 3
	c := nrf.start(t)
	p := testProfile(t)
	s := &script{steps: []func(){
		func() { nrf.set(func(f *fakeNRF) { f.fail = http.StatusInternalServerError }) },
		nil, nil,
		func() { nrf.set(func(f *fakeNRF) { f.fail = 0 }) },
		nil,
	}}
	(&Agent{Client: c, Profiles: []Profile{p}, Log: discard, sleep: s.sleep}).Run(context.Background())

	sec := time.Second
	// 3 s interval; failures retried after 1 s, 2 s, then min(4 s, 3 s); success: 3 s again.
	assert.Equal(t, []time.Duration{3 * sec, 1 * sec, 2 * sec, 3 * sec, 3 * sec, 3 * sec}, s.waits)
	assert.True(t, nrf.registered(p.InstanceID), "a failed heartbeat does not drop the registration")
}

// The NRF may answer a heartbeat with the profile and a new interval (TS 29.510 clause
// 5.2.2.3.2); the next heartbeats follow it.
func TestAgent_FollowsNewInterval(t *testing.T) {
	nrf := newFakeNRF(t)
	c := nrf.start(t)
	p := testProfile(t)
	s := &script{steps: []func(){
		func() { nrf.set(func(f *fakeNRF) { f.heartbeatOK, f.heartbeat = true, 20 }) },
		nil,
	}}
	(&Agent{Client: c, Profiles: []Profile{p}, Log: discard, sleep: s.sleep}).Run(context.Background())
	assert.Equal(t, []time.Duration{10 * time.Second, 20 * time.Second, 20 * time.Second}, s.waits)
}

func TestAgent_FallbackHeartbeat(t *testing.T) {
	nrf := newFakeNRF(t)
	nrf.heartbeat = 0 // the answer carries no heartBeatTimer
	c := nrf.start(t)
	p := testProfile(t)
	s := &script{}
	(&Agent{Client: c, Profiles: []Profile{p}, Log: discard, sleep: s.sleep}).Run(context.Background())
	assert.Equal(t, []time.Duration{fallbackHeartbeat}, s.waits)

	p.Heartbeat = 15 * time.Second
	s = &script{}
	(&Agent{Client: c, Profiles: []Profile{p}, Log: discard, sleep: s.sleep}).Run(context.Background())
	assert.Equal(t, []time.Duration{15 * time.Second}, s.waits, "the proposal before the fallback")
}

// Each profile is kept on its own: a UDR the NRF refuses does not hold up the UDM.
func TestAgent_ProfilesIndependent(t *testing.T) {
	nrf := newFakeNRF(t)
	ps, err := Build([]byte(twoProfiles), Options{TLS: true}, testAPIs)
	require.NoError(t, err)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == nfInstancesPath+udrID {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		nrf.ServeHTTP(w, r)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL+"/", srv.Client())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	a := &Agent{Client: c, Profiles: ps, Log: discard, sleep: func(ctx context.Context, d time.Duration) bool {
		if nrf.registered(udmID) {
			cancel()
		}
		<-time.After(time.Millisecond)
		return ctx.Err() == nil
	}}
	a.Run(ctx)
	assert.True(t, nrf.registered(udmID))
	assert.NotErrorIs(t, ctx.Err(), context.DeadlineExceeded, "the UDM registered while the UDR was refused")
}
