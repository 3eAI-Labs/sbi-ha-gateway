// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nrf

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	natsserver "github.com/nats-io/nats-server/v2/server"
	natsgo "github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func natsConn(t *testing.T) *natsgo.Conn {
	t.Helper()
	s, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	require.NoError(t, err)
	go s.Start()
	require.True(t, s.ReadyForConnections(5*time.Second))
	t.Cleanup(s.Shutdown)
	nc, err := natsgo.Connect(s.ClientURL())
	require.NoError(t, err)
	t.Cleanup(nc.Close)
	return nc
}

// replica is one replica's watcher, subscribed to the SMSF, and its notification endpoint.
func replica(t *testing.T, nc *natsgo.Conn) (*Watcher, *fakeNRF, http.Handler) {
	t.Helper()
	nrf := newFakeNRF(t)
	d, w, _ := watched(t, nrf)
	_, err := smsfRoot(d)
	require.NoError(t, err)
	w.step(context.Background())
	n, err := NewNotifications(w, nc, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	t.Cleanup(n.Close)
	r := chi.NewRouter()
	n.Route(r)
	return w, nrf, r
}

func notify(h http.Handler, path, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const changed = `{"event":"NF_PROFILE_CHANGED","nfInstanceUri":"https://nrf.example/nnrf-nfm/v1/nf-instances/` + smsfID + `","profileChanges":[]}`

// A notification is acted on by the replica that subscribed, whichever replica the NRF
// reached; one to a replica no longer there, or to no subscription, is answered 404.
func TestNotifications(t *testing.T) {
	nc := natsConn(t)
	a, nrfA, ha := replica(t, nc)
	b, nrfB, _ := replica(t, nc)
	keyA, keyB := onlyKey(t, nrfA, a), onlyKey(t, nrfB, b)

	// To A, at A.
	rec := notify(ha, NotifyPath+a.Replica()+"/"+keyA, "application/json", changed)
	assert.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
	assert.True(t, a.disc.found[discoveryKey{"SMSF", smsfID, "nsmsf-sms", "v2"}].until.IsZero())

	// To B, at A: handed over NATS.
	rec = notify(ha, NotifyPath+b.Replica()+"/"+keyB, "application/json; charset=utf-8", changed)
	assert.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
	assert.True(t, b.disc.found[discoveryKey{"SMSF", smsfID, "nsmsf-sms", "v2"}].until.IsZero())

	// A key of A's at B's name, and B's key at A's: no such subscription.
	for _, path := range []string{NotifyPath + b.Replica() + "/" + keyA, NotifyPath + a.Replica() + "/" + keyB} {
		rec = notify(ha, path, "application/json", changed)
		assert.Equal(t, http.StatusNotFound, rec.Code, path)
		assert.Contains(t, rec.Body.String(), "SUBSCRIPTION_NOT_FOUND")
	}

	// A replica that stopped: no responder.
	rec = notify(ha, NotifyPath+strings.Repeat("0", 32)+"/"+keyB, "application/json", changed)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// What is no notification is refused before any replica acts on it.
func TestNotifications_Malformed(t *testing.T) {
	nc := natsConn(t)
	a, nrfA, h := replica(t, nc)
	path := NotifyPath + a.Replica() + "/" + onlyKey(t, nrfA, a)
	for _, c := range []struct {
		path, contentType, body string
		status                  int
	}{
		{path, "text/plain", changed, http.StatusUnsupportedMediaType},
		{path, "application/json", `{"event":"NF_DEREGISTERED"}`, http.StatusBadRequest},
		{path, "application/json", `[`, http.StatusBadRequest},
		{NotifyPath + a.Replica() + "/not-a-key", "application/json", changed, http.StatusNotFound},
		{NotifyPath + "ABC/" + strings.Repeat("0", 32), "application/json", changed, http.StatusNotFound},
	} {
		rec := notify(h, c.path, c.contentType, c.body)
		assert.Equal(t, c.status, rec.Code, "%s %s %s", c.path, c.contentType, c.body)
	}
	assert.False(t, a.disc.found[discoveryKey{"SMSF", smsfID, "nsmsf-sms", "v2"}].until.IsZero(), "nothing expired")
}
