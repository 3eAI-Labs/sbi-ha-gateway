// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sbiclient "github.com/3eAI-Labs/sbi-ha-gateway-client"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/models"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/nats"
	cgaudit "github.com/3eAI-Labs/sbi-ha-gateway/internal/platform/audit"
	"github.com/go-chi/chi/v5"
	natsserver "github.com/nats-io/nats-server/v2/server"
	gnats "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const itSupi = "imsi-001010000000001"

// One call per NATS request in the handlers. audited: the handler emits an audit event on
// success.
var itCalls = []struct {
	method, path, body string
	audited            bool
}{
	{"POST", "/nudm-ueau/v1/" + itSupi + "/security-information/generate-auth-data", `{"servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org","ausfInstanceId":"ausf-1"}`, true},
	{"POST", "/nudm-ueau/v1/" + itSupi + "/auth-events", `{"nfInstanceId":"ausf-1","success":true,"timeStamp":"2026-10-17T10:00:00Z","authType":"5G_AKA","servingNetworkName":"sn"}`, true},
	{"PUT", "/nudm-uecm/v1/" + itSupi + "/registrations/amf-3gpp-access", `{"amfInstanceId":"amf-1","ratType":"NR","deregCallbackUri":"http://amf/cb","guami":{"plmnId":{"mcc":"001","mnc":"01"},"amfId":"cafe00"}}`, true},
	{"PATCH", "/nudm-uecm/v1/" + itSupi + "/registrations/amf-3gpp-access", `{"purgeFlag":true}`, true},
	{"GET", "/nudm-uecm/v1/" + itSupi + "/registrations/amf-3gpp-access", ``, false},
	{"PUT", "/nudm-uecm/v1/" + itSupi + "/registrations/smf-registrations/5", `{"smfInstanceId":"smf-1","pduSessionId":5,"singleNssai":{"sst":1},"dnn":"internet","plmnId":{"mcc":"001","mnc":"01"}}`, true},
	{"PATCH", "/nudm-uecm/v1/" + itSupi + "/registrations/smf-registrations/5", `{"pgwFqdn":"pgw.example"}`, true},
	{"DELETE", "/nudm-uecm/v1/" + itSupi + "/registrations/smf-registrations/5", ``, true},
	{"PUT", "/nudm-uecm/v1/" + itSupi + "/registrations/smsf-3gpp-access", `{"smsfInstanceId":"smsf-1"}`, true},
	{"GET", "/nudm-uecm/v1/" + itSupi + "/registrations/smsf-3gpp-access", ``, false},
	{"DELETE", "/nudm-uecm/v1/" + itSupi + "/registrations/smsf-3gpp-access", ``, true},
	{"GET", "/nudm-uecm/v1/" + itSupi + "/registrations", ``, false},
	{"POST", "/nudm-mt/v1/" + itSupi + "/loc-info/provide-loc-info", `{"req5gsLoc":true}`, true},
	{"GET", "/nudr-dr/v1/subscription-data/" + itSupi + "/authentication-data/authentication-subscription", ``, false},
	{"PUT", "/nudr-dr/v1/subscription-data/" + itSupi + "/context-data/amf-3gpp-access", `{"amfInstanceId":"amf-1"}`, false},
}

// itReplies is what an application answers on each request subject.
var itReplies = map[string]string{
	sbiclient.SubjectAuthRequest:          `{"authVector":{"rand":"r","autn":"a","xresStar":"x","kAusf":"k"}}`,
	sbiclient.SubjectAuthConfirm:          `{"authEventId":"ev-1"}`,
	sbiclient.SubjectMobilityRegistration: `{}`,
	sbiclient.SubjectMobilityQuery:        `{"amf3GppAccessRegistration":{"amfInstanceId":"amf-1"}}`,
	sbiclient.SubjectLocationInfo:         `{"currentLoc":true}`,
	sbiclient.SubjectDataQuery:            `{"payload":{"a":1}}`,
	sbiclient.SubjectDataUpdate:           `{}`,
}

const itTimeout = 200 * time.Millisecond

// The handlers against a real NATS server, one phase after another:
//   - an application answers with results: every call succeeds, state changes are audited;
//   - it answers with an ErrorReply: the network function gets its status and
//     ProblemDetails, and nothing is audited;
//   - it is subscribed but silent: 504 after the request timeout, not when the network
//     function gives up;
//   - nothing is subscribed: 504 at once;
//   - a stream captures 5g.> — what a back end that consumes its requests through
//     JetStream sets up: 500, and nothing is audited.
func TestHandlers_RealNATS(t *testing.T) {
	s, err := natsserver.NewServer(&natsserver.Options{Port: -1, JetStream: true, StoreDir: t.TempDir()})
	require.NoError(t, err)
	go s.Start()
	require.True(t, s.ReadyForConnections(10*time.Second))
	defer s.Shutdown()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	client, err := nats.NewClient(s.ClientURL(), log)
	require.NoError(t, err)
	defer client.Close()
	nc := client.GetConn()

	var audited atomic.Int64
	_, err = nc.Subscribe("audit.test", func(*gnats.Msg) { audited.Add(1) })
	require.NoError(t, err)
	cgaudit.SetPublisher(nc, "audit.test")
	defer cgaudit.SetPublisher(nil, "")

	r := chi.NewRouter()
	handlers.NewAuthHandler(log, client, itTimeout).RegisterRoutes(r)
	handlers.NewMobilityHandler(log, client, itTimeout).RegisterRoutes(r)
	handlers.NewMTHandler(log, client, itTimeout).RegisterRoutes(r)
	handlers.NewDataHandler(log, client, itTimeout).RegisterRoutes(r)

	// A network function that gives up after 2 s, so that a request the gateway does not
	// time out itself fails the test instead of hanging it.
	serve := func(method, path, body string) *httptest.ResponseRecorder {
		var rd io.Reader
		if body != "" {
			rd = bytes.NewBufferString(body)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(method, path, rd).WithContext(ctx))
		return rec
	}
	// noAudit checks that a phase emitted no audit event. Events go out through a queue;
	// give a wrongly emitted one time to arrive.
	noAudit := func(t *testing.T, before int64) {
		time.Sleep(300 * time.Millisecond)
		assert.Equal(t, before, audited.Load(), "audit events")
	}

	t.Run("results", func(t *testing.T) {
		app, err := nc.Subscribe("5g.>", func(m *gnats.Msg) { _ = m.Respond([]byte(itReplies[m.Subject])) })
		require.NoError(t, err)
		defer func() { require.NoError(t, app.Unsubscribe()) }()
		var want int64
		for _, c := range itCalls {
			rec := serve(c.method, c.path, c.body)
			assert.Less(t, rec.Code, 300, "%s %s: %s", c.method, c.path, rec.Body.String())
			if c.audited {
				want++
			}
		}
		require.Eventually(t, func() bool { return audited.Load() == want }, 5*time.Second, 20*time.Millisecond)
	})

	t.Run("error reply", func(t *testing.T) {
		const problem = `{"status":404,"cause":"USER_NOT_FOUND","detail":"no such subscriber","invalidParams":[{"param":"/supi"}]}`
		app, err := nc.Subscribe("5g.>", func(m *gnats.Msg) { _ = m.Respond([]byte(`{"problemDetails":` + problem + `}`)) })
		require.NoError(t, err)
		defer func() { require.NoError(t, app.Unsubscribe()) }()
		before := audited.Load()
		for _, c := range itCalls {
			rec := serve(c.method, c.path, c.body)
			assert.Equal(t, http.StatusNotFound, rec.Code, "%s %s", c.method, c.path)
			assert.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"), "%s %s", c.method, c.path)
			assert.JSONEq(t, problem, rec.Body.String(), "%s %s", c.method, c.path)
		}
		noAudit(t, before)
	})

	t.Run("silent application", func(t *testing.T) {
		app, err := nc.Subscribe("5g.>", func(*gnats.Msg) {})
		require.NoError(t, err)
		defer func() { require.NoError(t, app.Unsubscribe()) }()
		before := audited.Load()
		for _, c := range itCalls {
			start := time.Now()
			rec := serve(c.method, c.path, c.body)
			elapsed := time.Since(start)
			assertProblem(t, rec, http.StatusGatewayTimeout, "TARGET_NF_NOT_REACHABLE", c.method+" "+c.path)
			assert.GreaterOrEqual(t, elapsed, itTimeout, "%s %s", c.method, c.path)
			assert.Less(t, elapsed, 5*itTimeout, "%s %s", c.method, c.path)
		}
		noAudit(t, before)
	})

	t.Run("no application", func(t *testing.T) {
		before := audited.Load()
		for _, c := range itCalls {
			start := time.Now()
			rec := serve(c.method, c.path, c.body)
			assertProblem(t, rec, http.StatusGatewayTimeout, "TARGET_NF_NOT_REACHABLE", c.method+" "+c.path)
			assert.Less(t, time.Since(start), itTimeout, "%s %s: no responders is known at once", c.method, c.path)
		}
		noAudit(t, before)
	})

	t.Run("stream captures 5g.>", func(t *testing.T) {
		js, err := client.JetStream()
		require.NoError(t, err)
		_, err = js.CreateStream(t.Context(), jetstream.StreamConfig{Name: "CORE_EVENTS", Subjects: []string{"5g.>"}})
		require.NoError(t, err)
		before := audited.Load()
		for _, c := range itCalls {
			rec := serve(c.method, c.path, c.body)
			assertProblem(t, rec, http.StatusInternalServerError, "SYSTEM_FAILURE", c.method+" "+c.path)
			assert.False(t, strings.Contains(rec.Body.String(), "CORE_EVENTS"), "stream name in the problem detail")
		}
		noAudit(t, before)
	})
}

func assertProblem(t *testing.T, rec *httptest.ResponseRecorder, status int, cause, msg string) {
	t.Helper()
	assert.Equal(t, status, rec.Code, "%s: %s", msg, rec.Body.String())
	var prob models.ProblemDetails
	if assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &prob), msg) {
		assert.Equal(t, cause, prob.Cause, msg)
	}
}
