// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nrf

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/free5gc/openapi/models"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
)

// NotifyPath is where, under the SBI port's {apiRoot}, the NRF's notifications to the
// gateway's subscriptions go: {apiRoot}/nrf-notify/v1/{replica}/{key}. A callback URI is the
// consumer's to choose (TS 29.510 clause 5.2.2.5.2); these name the replica that subscribed
// and, with key, the subscription.
const NotifyPath = "/nrf-notify/v1/"

// subscriptionLifetime is the validity time the gateway asks for: a subscription the gateway
// cannot remove (its pod was killed) lasts at most this long at an NRF that expires
// subscriptions. The gateway's choice; it renews at half the lifetime granted.
const subscriptionLifetime = time.Hour

// maxRetryDelay bounds the wait between attempts at a subscription the NRF refused or did not
// answer.
const maxRetryDelay = 5 * time.Minute

// unsubscribeTimeout bounds the removal of the subscriptions when the pod stops.
const unsubscribeTimeout = 5 * time.Second

// Watcher keeps one subscription (NFStatusSubscribe, TS 29.510 clause 5.2.2.5) per NF instance
// its Discovery found, so that the instance's deregistration or a change of its profile ends
// the cached result before its validityPeriod does. Each replica subscribes for the instances
// it cached itself: the caches are per replica. A notification is a hint, never an address:
// it expires the instance's results, or forgets them when the instance deregistered, and the
// next call asks the NRF again, as the requester, over the NRF connection. The notification's
// sender is not authenticated (the NRF sends no token the gateway could verify; free5GC's, for
// one, is for the NF type, with no scope); the key in the callback URI, 128 random bits, is
// what a sender must know.
type Watcher struct {
	client   *Client
	disc     *Discovery
	callback string // {apiRoot}/nrf-notify/v1/{replica}/
	replica  string
	log      *slog.Logger
	now      func() time.Time

	mu   sync.Mutex
	subs map[string]*subscription // by watched instance ID
	keys map[string]string        // callback key → instance ID
	kick chan struct{}
}

type subscription struct {
	nfType   string
	key      string
	id       string    // the NRF's subscriptionId; "" until it created one
	expires  time.Time // its validity time; zero: none known
	due      time.Time // when it is next created or renewed
	failures int
	removed  bool // to delete at the NRF, then forget
}

// NewWatcher subscribes, from now on, to each NF instance d finds, with callback URIs under
// apiRoot, the {apiRoot} the NRF reaches the gateway's SBI port at (https when the port serves
// TLS, else http). Run does the subscribing.
func NewWatcher(d *Discovery, apiRoot string, tls bool, log *slog.Logger) (*Watcher, error) {
	u, err := url.Parse(apiRoot)
	scheme := "http"
	if tls {
		scheme = "https"
	}
	if err != nil || u.Scheme != scheme || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, fmt.Errorf("NRF_NOTIFICATION_API_ROOT %q: want %s://host[:port][/prefix], the SBI port's {apiRoot}", apiRoot, scheme)
	}
	w := &Watcher{
		client:  d.client,
		disc:    d,
		replica: randomHex(),
		log:     log,
		now:     time.Now,
		subs:    map[string]*subscription{},
		keys:    map[string]string{},
		kick:    make(chan struct{}, 1),
	}
	w.callback = strings.TrimSuffix(apiRoot, "/") + NotifyPath + w.replica + "/"
	d.mu.Lock()
	d.watch = w
	d.mu.Unlock()
	return w, nil
}

// Replica names this replica in its callback URIs.
func (w *Watcher) Replica() string { return w.replica }

// randomHex is 128 random bits, in hexadecimal.
func randomHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // never fails (crypto/rand)
	return hex.EncodeToString(b)
}

// watch subscribes to the instance, unless a subscription to it exists.
func (w *Watcher) watch(nfType, instanceID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if s, ok := w.subs[instanceID]; ok {
		if s.removed {
			s.removed = false
			w.keys[s.key] = instanceID
		}
		return
	}
	s := &subscription{nfType: nfType, key: randomHex(), due: w.now()}
	w.subs[instanceID] = s
	w.keys[s.key] = instanceID
	w.wake()
}

// unwatch removes the subscription to the instance: its notifications are answered 404 from
// now on.
func (w *Watcher) unwatch(instanceID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if s, ok := w.subs[instanceID]; ok && !s.removed {
		s.removed = true
		delete(w.keys, s.key)
		w.wake()
	}
}

func (w *Watcher) wake() {
	select {
	case w.kick <- struct{}{}:
	default:
	}
}

// Deliver acts on a notification (NFStatusNotify, clause 5.2.2.6) of event to the subscription
// key names, and returns the status to answer the NRF with: 404 when this replica has no such
// subscription (clause 5.2.2.6.2 step 2b), else 204.
func (w *Watcher) Deliver(key string, event models.Nrf_NFMgmt_NotificationEventType) int {
	w.mu.Lock()
	instanceID, ok := w.keys[key]
	w.mu.Unlock()
	if !ok {
		metrics.RecordNRFNotification(string(event), "unknown_subscription")
		return 404
	}
	if event == models.Nrf_NFMgmt_NotificationEventType_DEREGISTERED {
		w.disc.forgetInstance(instanceID) // and unwatches it
	} else {
		// NF_PROFILE_CHANGED, and what else an NRF may send (NF_REGISTERED, an event of a
		// later release): the next call asks the NRF.
		w.disc.expireInstance(instanceID)
	}
	metrics.RecordNRFNotification(string(event), "accepted")
	w.log.Info("NRF notification: the discovered instance is looked up again",
		slog.String("event", string(event)), slog.String("nf_instance_id", instanceID))
	return 204
}

// Run creates, renews and removes the subscriptions until ctx ends, then removes them all
// (within unsubscribeTimeout): the replica's callback URIs die with it.
func (w *Watcher) Run(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			w.close()
			return
		case <-w.kick:
		case <-timer.C:
		}
		next := w.step(ctx)
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(max(next.Sub(w.now()), 0))
	}
}

// step does what is due and returns when something is next due.
func (w *Watcher) step(ctx context.Context) time.Time {
	now := w.now()
	next := now.Add(subscriptionLifetime)
	w.mu.Lock()
	type item struct {
		instanceID string
		s          subscription
	}
	var due []item
	for id, s := range w.subs {
		if s.removed || !now.Before(s.due) {
			due = append(due, item{id, *s})
		} else if s.due.Before(next) {
			next = s.due
		}
	}
	w.mu.Unlock()

	for _, it := range due {
		if ctx.Err() != nil {
			break
		}
		if t := w.act(ctx, it.instanceID, it.s); !t.IsZero() && t.Before(next) {
			next = t
		}
	}
	return next
}

// act creates, renews or removes the subscription to instanceID, of which s is a copy, and
// returns when it is next due; zero when it is gone.
func (w *Watcher) act(ctx context.Context, instanceID string, s subscription) time.Time {
	p := w.disc.requester
	if s.removed {
		if s.id != "" {
			if err := w.client.unsubscribe(ctx, p, s.id); err != nil {
				w.log.Warn("NRF unsubscribe failed; the subscription lapses at its validity time",
					slog.String("nf_instance_id", instanceID), slog.Any("error", err))
			}
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		switch cur := w.subs[instanceID]; {
		case cur == nil || cur.key != s.key:
		case cur.removed:
			delete(w.subs, instanceID)
		default:
			// Watched again meanwhile: subscribe anew.
			cur.id, cur.expires, cur.due = "", time.Time{}, w.now()
			return cur.due
		}
		return time.Time{}
	}

	now := w.now()
	ask := now.Add(subscriptionLifetime)
	var id string
	var granted time.Time
	var err error
	if s.id == "" || (!s.expires.IsZero() && !now.Before(s.expires)) {
		id, granted, err = w.client.subscribe(ctx, p, s.nfType, instanceID, w.callback+s.key, ask)
	} else {
		id = s.id
		granted, err = w.client.renew(ctx, p, s.id, ask)
		if IsNotFound(err) {
			// The NRF lost it (a restart, an expiry): subscribe anew.
			id, granted, err = w.client.subscribe(ctx, p, s.nfType, instanceID, w.callback+s.key, ask)
		}
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	cur := w.subs[instanceID]
	if cur == nil || cur.key != s.key {
		return time.Time{}
	}
	if err != nil {
		cur.failures++
		cur.due = now.Add(min(time.Second<<min(cur.failures-1, 9), maxRetryDelay))
		w.log.Warn("NRF subscription failed; MT SMS use the discovered instance until its validityPeriod ends",
			slog.String("nf_instance_id", instanceID), slog.Int("failures", cur.failures),
			slog.Time("next_attempt", cur.due), slog.Any("error", err))
		return cur.due
	}
	if granted.IsZero() {
		granted = ask // the NRF gave none: what was asked for
	}
	cur.id, cur.expires, cur.failures = id, granted, 0
	// Renewed at half the lifetime granted, at least a second on.
	cur.due = now.Add(max(granted.Sub(now)/2, time.Second))
	if cur.removed {
		// Removed while it was being created: remove it at the NRF next.
		return now
	}
	return cur.due
}

// close removes every subscription at the NRF, within unsubscribeTimeout.
func (w *Watcher) close() {
	ctx, cancel := context.WithTimeout(context.Background(), unsubscribeTimeout)
	defer cancel()
	w.mu.Lock()
	ids := map[string]string{}
	for instanceID, s := range w.subs {
		if s.id != "" {
			ids[instanceID] = s.id
		}
		delete(w.keys, s.key)
	}
	w.subs = map[string]*subscription{}
	w.mu.Unlock()
	for instanceID, id := range ids {
		if err := w.client.unsubscribe(ctx, w.disc.requester, id); err != nil {
			w.log.Warn("NRF unsubscribe failed at shutdown; the subscription lapses at its validity time",
				slog.String("nf_instance_id", instanceID), slog.Any("error", err))
		}
	}
}
