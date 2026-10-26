// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nrf

import (
	"encoding/json"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/free5gc/openapi/models"
	"github.com/go-chi/chi/v5"
	natsgo "github.com/nats-io/nats.go"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
)

// NotifySubjectPrefix is the NATS subject a replica receives, at NotifySubjectPrefix +
// {replica}, the notifications to its subscriptions that reached another replica: the NRF
// sends them to the installation's address, which any replica serves. Core request/reply,
// the gateway's alone.
const NotifySubjectPrefix = "sbi.internal.nrf.notify."

// relayTimeout bounds the hand-over of a notification to the replica that subscribed.
const relayTimeout = 2 * time.Second

// hex128 is a replica or a key: 128 bits in lower-case hexadecimal (randomHex).
var hex128 = regexp.MustCompile(`^[0-9a-f]{32}$`)

// relayed is a notification handed from the replica the NRF reached to the one that
// subscribed: what Deliver needs, not the notification (the profile may be large).
type relayed struct {
	Key   string `json:"key"`
	Event string `json:"event"`
}

type relayReply struct {
	Status int `json:"status"`
}

// Notifications serves the NRF's notifications (NFStatusNotify, TS 29.510 clause 5.2.2.6) to
// the subscriptions of every replica of the installation: those of this replica's Watcher
// itself, the others' through NATS.
type Notifications struct {
	watcher *Watcher
	nc      *natsgo.Conn
	sub     *natsgo.Subscription
	problem handlers.BaseHandler
}

// NewNotifications serves w's notifications, and receives over nc those to w's subscriptions
// that another replica received, until Close.
func NewNotifications(w *Watcher, nc *natsgo.Conn, log *slog.Logger) (*Notifications, error) {
	n := &Notifications{watcher: w, nc: nc, problem: handlers.BaseHandler{Log: log}}
	sub, err := nc.Subscribe(NotifySubjectPrefix+w.replica, func(m *natsgo.Msg) {
		var r relayed
		status := http.StatusBadRequest
		if json.Unmarshal(m.Data, &r) == nil && r.Key != "" && r.Event != "" {
			status = w.Deliver(r.Key, models.Nrf_NFMgmt_NotificationEventType(r.Event))
		}
		reply, _ := json.Marshal(relayReply{status})
		_ = m.Respond(reply)
	})
	if err != nil {
		return nil, err
	}
	n.sub = sub
	return n, nil
}

// Close stops receiving the notifications other replicas hand over.
func (n *Notifications) Close() { _ = n.sub.Unsubscribe() }

// Route mounts the callback, POST {NotifyPath}{replica}/{key}, on r.
func (n *Notifications) Route(r chi.Router) {
	r.Post(NotifyPath+"{replica}/{key}", n.ServeHTTP)
}

// ServeHTTP answers a notification: 204 once the replica that subscribed acted on it, 404
// when no replica has the subscription (clause 5.2.2.6.2 step 2b), 400 for a body that is no
// NotificationData.
func (n *Notifications) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	replica, key := chi.URLParam(r, "replica"), chi.URLParam(r, "key")
	if !hex128.MatchString(replica) || !hex128.MatchString(key) {
		metrics.RecordNRFNotification("", "unknown_subscription")
		n.problem.WriteProblem(w, http.StatusNotFound, "SUBSCRIPTION_NOT_FOUND", "no such subscription")
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		metrics.RecordNRFNotification("", "malformed")
		n.problem.WriteProblem(w, http.StatusUnsupportedMediaType, "", "want application/json")
		return
	}
	var data models.Nrf_NFMgmt_NotificationData
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, handlers.MaxRequestBodyBytes))
	if err := dec.Decode(&data); err != nil || data.Event == "" || data.NfInstanceUri == "" {
		metrics.RecordNRFNotification("", "malformed")
		n.problem.WriteProblem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING",
			"want a NotificationData with event and nfInstanceUri")
		return
	}
	var status int
	if replica == n.watcher.replica {
		status = n.watcher.Deliver(key, data.Event)
	} else {
		var err error
		if status, err = n.relay(replica, key, data.Event); err != nil {
			n.problem.WriteProblem(w, http.StatusInternalServerError, "SYSTEM_FAILURE",
				"the notification could not be handed to the replica that subscribed")
			return
		}
	}
	if status == http.StatusNoContent {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	n.problem.WriteProblem(w, http.StatusNotFound, "SUBSCRIPTION_NOT_FOUND", "no such subscription")
}

// relay hands the notification to the replica that subscribed and returns the status it
// answered; 404 when no replica of that name is left (its pod stopped).
func (n *Notifications) relay(replica, key string, event models.Nrf_NFMgmt_NotificationEventType) (int, error) {
	data, _ := json.Marshal(relayed{key, string(event)})
	m, err := n.nc.Request(NotifySubjectPrefix+replica, data, relayTimeout)
	if errors.Is(err, natsgo.ErrNoResponders) {
		metrics.RecordNRFNotification(string(event), "unknown_subscription")
		return http.StatusNotFound, nil
	}
	if err != nil {
		metrics.RecordNRFNotification(string(event), "relay_failed")
		n.problem.Log.Warn("NRF notification not handed to the replica that subscribed",
			slog.String("event", string(event)), slog.Any("error", err))
		return 0, err
	}
	var reply relayReply
	if json.Unmarshal(m.Data, &reply) != nil || reply.Status == 0 {
		metrics.RecordNRFNotification(string(event), "relay_failed")
		return 0, errors.New("the replica's reply is no status: " + strings.TrimSpace(string(m.Data)))
	}
	return reply.Status, nil
}
