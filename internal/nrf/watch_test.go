// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nrf

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/free5gc/openapi/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const gatewayRoot = "https://sbi-gw.example:8443"

// watched is discovery from nrf as the SMS_GMSC, with a Watcher, and the SMSF registered.
func watched(t *testing.T, nrf *fakeNRF) (*Discovery, *Watcher, *clock) {
	t.Helper()
	c := nrf.start(t)
	d, clk := gmscDiscovery(t, nrf, c)
	w, err := NewWatcher(d, gatewayRoot, true, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	w.now = clk.now
	nrf.set(func(f *fakeNRF) { f.instances[smsfID] = smsfProfile() })
	return d, w, clk
}

// key is the callback key of the only subscription the NRF holds.
func onlyKey(t *testing.T, nrf *fakeNRF, w *Watcher) string {
	t.Helper()
	nrf.mu.Lock()
	defer nrf.mu.Unlock()
	require.Len(t, nrf.subscriptions, 1)
	for _, s := range nrf.subscriptions {
		uri := s["nfStatusNotificationUri"].(string)
		key, ok := strings.CutPrefix(uri, gatewayRoot+NotifyPath+w.Replica()+"/")
		require.True(t, ok, uri)
		return key
	}
	return ""
}

// An SMSF discovered is subscribed to, as the SMS_GMSC, for its deregistration and profile
// changes, with a callback URI naming the replica and the subscription, for an hour.
func TestWatcher_Subscribes(t *testing.T) {
	nrf := newFakeNRF(t)
	_, w, clk := watched(t, nrf)
	d := w.disc
	_, err := smsfRoot(d)
	require.NoError(t, err)

	w.step(context.Background())
	require.Len(t, nrf.subscribeReqs, 1)
	s := nrf.subscribeReqs[0]
	assert.Equal(t, map[string]any{"nfInstanceId": smsfID}, s["subscrCond"])
	assert.Equal(t, "SMS_GMSC", s["reqNfType"])
	assert.Equal(t, gmscID, s["reqNfInstanceId"])
	assert.Equal(t, []any{"NF_DEREGISTERED", "NF_PROFILE_CHANGED"}, s["reqNotifEvents"])
	validity, err := time.Parse(time.RFC3339, s["validityTime"].(string))
	require.NoError(t, err)
	assert.Equal(t, clk.t.Add(time.Hour).Unix(), validity.Unix())
	assert.Len(t, onlyKey(t, nrf, w), 32)

	// Further calls, cached or not, subscribe no more.
	_, err = smsfRoot(d)
	require.NoError(t, err)
	w.step(context.Background())
	assert.Len(t, nrf.subscribeReqs, 1)
}

// A profile change notified ends the cached result: the next call asks the NRF.
func TestWatcher_ProfileChanged(t *testing.T) {
	nrf := newFakeNRF(t)
	d, w, _ := watched(t, nrf)
	_, err := smsfRoot(d)
	require.NoError(t, err)
	w.step(context.Background())

	assert.Equal(t, 204, w.Deliver(onlyKey(t, nrf, w), models.Nrf_NFMgmt_NotificationEventType_PROFILE_CHANGED))
	nrf.set(func(f *fakeNRF) {
		svc := f.instances[smsfID]["nfServices"].([]any)[0].(map[string]any)
		svc["apiPrefix"] = "/moved"
	})
	root, err := smsfRoot(d)
	require.NoError(t, err)
	assert.Equal(t, "https://smsf.example:8443/moved", root)
	assert.Len(t, nrf.discoveries, 2)
	assert.Equal(t, 1, nrf.subscriptionCount(), "the subscription stays")
}

// A deregistration notified forgets the instance and removes the subscription; a later
// notification to it is answered 404.
func TestWatcher_Deregistered(t *testing.T) {
	nrf := newFakeNRF(t)
	d, w, _ := watched(t, nrf)
	_, err := smsfRoot(d)
	require.NoError(t, err)
	w.step(context.Background())
	key := onlyKey(t, nrf, w)

	nrf.set(func(f *fakeNRF) { delete(f.instances, smsfID) })
	assert.Equal(t, 204, w.Deliver(key, models.Nrf_NFMgmt_NotificationEventType_DEREGISTERED))
	assert.Equal(t, 404, w.Deliver(key, models.Nrf_NFMgmt_NotificationEventType_PROFILE_CHANGED))
	w.step(context.Background())
	assert.Equal(t, 0, nrf.subscriptionCount())
	assert.Empty(t, w.subs)

	_, err = smsfRoot(d)
	assert.ErrorIs(t, err, ErrNotDiscovered)
	assert.Len(t, nrf.discoveries, 2)
}

// An instance the NRF no longer knows is forgotten, and its subscription removed.
func TestWatcher_NotDiscovered(t *testing.T) {
	nrf := newFakeNRF(t)
	d, w, clk := watched(t, nrf)
	_, err := smsfRoot(d)
	require.NoError(t, err)
	w.step(context.Background())

	nrf.set(func(f *fakeNRF) { delete(f.instances, smsfID) })
	clk.t = clk.t.Add(61 * time.Second) // past the validityPeriod
	_, err = smsfRoot(d)
	require.ErrorIs(t, err, ErrNotDiscovered)
	w.step(context.Background())
	assert.Equal(t, 0, nrf.subscriptionCount())
}

// A subscription is renewed at half the validity time granted; one the NRF lost is created
// anew.
func TestWatcher_Renews(t *testing.T) {
	nrf := newFakeNRF(t)
	d, w, clk := watched(t, nrf)
	_, err := smsfRoot(d)
	require.NoError(t, err)
	w.step(context.Background())

	clk.t = clk.t.Add(29 * time.Minute)
	w.step(context.Background())
	assert.Empty(t, nrf.renewals, "not yet due")

	clk.t = clk.t.Add(time.Minute)
	w.step(context.Background())
	require.Len(t, nrf.renewals, 1)
	assert.Equal(t, "replace", nrf.renewals[0][0]["op"])
	assert.Equal(t, "/validityTime", nrf.renewals[0][0]["path"])
	assert.Equal(t, clk.t.Add(time.Hour).UTC().Format(time.RFC3339), nrf.renewals[0][0]["value"])

	// The NRF assigns a shorter validity: the next renewal comes at half of it.
	nrf.set(func(f *fakeNRF) { f.grant = clk.t.Add(time.Hour + 10*time.Minute).UTC().Format(time.RFC3339) })
	clk.t = clk.t.Add(30 * time.Minute)
	w.step(context.Background())
	require.Len(t, nrf.renewals, 2)
	assert.Equal(t, clk.t.Add(20*time.Minute), w.subs[smsfID].due)

	// Lost (an NRF restart): subscribed anew, with the same callback URI.
	key := onlyKey(t, nrf, w)
	nrf.set(func(f *fakeNRF) { f.subscriptions = map[string]map[string]any{} })
	clk.t = clk.t.Add(20 * time.Minute)
	w.step(context.Background())
	assert.Len(t, nrf.subscribeReqs, 2)
	assert.Equal(t, key, onlyKey(t, nrf, w))
}

// A refused subscription is tried again, a second later, then two, ...; free5GC's answer
// without a Location header names the subscription in its body.
func TestWatcher_Retries(t *testing.T) {
	nrf := newFakeNRF(t)
	d, w, clk := watched(t, nrf)
	nrf.set(func(f *fakeNRF) { f.subFail, f.noLocation = 503, true })
	_, err := smsfRoot(d)
	require.NoError(t, err)

	w.step(context.Background())
	w.step(context.Background())
	assert.Equal(t, clk.t.Add(time.Second), w.subs[smsfID].due)
	clk.t = clk.t.Add(time.Second)
	w.step(context.Background())
	assert.Equal(t, clk.t.Add(2*time.Second), w.subs[smsfID].due)
	assert.Equal(t, []string{"SUB-POST", "SUB-POST"}, filter(nrf.callLog(), "SUB-"))

	nrf.set(func(f *fakeNRF) { f.subFail = 0 })
	clk.t = clk.t.Add(2 * time.Second)
	w.step(context.Background())
	assert.Equal(t, "sub-1", w.subs[smsfID].id)
	assert.Zero(t, w.subs[smsfID].failures)
}

// The subscriptions are removed when the pod stops.
func TestWatcher_RemovedOnStop(t *testing.T) {
	nrf := newFakeNRF(t)
	d, w, _ := watched(t, nrf)
	_, err := smsfRoot(d)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	require.Eventually(t, func() bool { return nrf.subscriptionCount() == 1 }, 5*time.Second, 10*time.Millisecond)
	cancel()
	<-done
	assert.Equal(t, 0, nrf.subscriptionCount())
}

// With OAuth the subscription goes with an NFManagement token, obtained on the first 401.
func TestWatcher_OAuth(t *testing.T) {
	nrf := newFakeNRF(t)
	nrf.oauth = true
	d, w, _ := watched(t, nrf)
	_, err := smsfRoot(d)
	require.NoError(t, err)
	w.step(context.Background())
	assert.Equal(t, 1, nrf.subscriptionCount())
	var scopes []string
	for _, q := range nrf.tokenReqs {
		scopes = append(scopes, q.Get("scope"))
	}
	assert.Contains(t, scopes, "nnrf-nfm")
}

// The callback {apiRoot} must be the SBI port's scheme.
func TestNewWatcher_APIRoot(t *testing.T) {
	nrf := newFakeNRF(t)
	c := nrf.start(t)
	d, _ := gmscDiscovery(t, nrf, c)
	for _, root := range []string{"http://sbi-gw.example", "https://", "https://sbi-gw.example/?q", "sbi-gw.example"} {
		_, err := NewWatcher(d, root, true, slog.New(slog.DiscardHandler))
		assert.Error(t, err, root)
	}
	w, err := NewWatcher(d, "http://sbi-gw.example:8080/", false, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	assert.Equal(t, "http://sbi-gw.example:8080/nrf-notify/v1/"+w.Replica()+"/", w.callback)
}

func filter(calls []string, prefix string) []string {
	var out []string
	for _, c := range calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}
