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
	"sync"
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

// One call per NATS subject and kind of reply. reply is what the application answers when
// it accepts the operation; audited: the gateway emits an audit event on success.
var itCalls = []struct {
	method, path, contentType, body string
	operation, reply                string
	audited                         bool
}{
	{"POST", "/nudm-ueau/v1/" + itSupi + "/security-information/generate-auth-data", "application/json",
		`{"servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org","ausfInstanceId":"ausf-1"}`,
		"GenerateAuthData", `{"body":{"authType":"5G_AKA","authenticationVector":{"avType":"5G_HE_AKA","rand":"r","xresStar":"x","autn":"a","kausf":"k"}}}`, true},
	{"POST", "/nudm-ueau/v1/" + itSupi + "/auth-events", "application/json",
		`{"nfInstanceId":"ausf-1","success":true,"timeStamp":"2026-10-17T10:00:00Z","authType":"5G_AKA","servingNetworkName":"sn"}`,
		"ConfirmAuth", `{"resourceId":"ev-1","body":{"nfInstanceId":"ausf-1","success":true}}`, true},
	{"PUT", "/nudm-uecm/v1/" + itSupi + "/registrations/amf-3gpp-access", "application/json",
		`{"amfInstanceId":"amf-1","ratType":"NR","deregCallbackUri":"http://amf/cb","guami":{"plmnId":{"mcc":"001","mnc":"01"},"amfId":"cafe00"}}`,
		"3GppRegistration", `{"status":201,"body":{"amfInstanceId":"amf-1"}}`, true},
	{"PATCH", "/nudm-uecm/v1/" + itSupi + "/registrations/amf-3gpp-access", "application/merge-patch+json",
		`{"purgeFlag":true}`, "Update3GppRegistration", `{"status":204}`, true},
	{"GET", "/nudm-uecm/v1/" + itSupi + "/registrations/amf-3gpp-access", "", ``,
		"Get3GppRegistration", `{"body":{"amfInstanceId":"amf-1"}}`, false},
	{"PUT", "/nudm-uecm/v1/" + itSupi + "/registrations/smf-registrations/5", "application/json",
		`{"smfInstanceId":"smf-1","pduSessionId":5,"singleNssai":{"sst":1},"dnn":"internet","plmnId":{"mcc":"001","mnc":"01"}}`,
		"Registration", `{"status":201,"body":{"smfInstanceId":"smf-1"}}`, true},
	{"DELETE", "/nudm-uecm/v1/" + itSupi + "/registrations/smf-registrations/5", "", ``,
		"SmfDeregistration", `{}`, true},
	{"GET", "/nudm-uecm/v1/" + itSupi + "/registrations", "", ``,
		"GetRegistrations", `{"body":{"amf3Gpp":{"amfInstanceId":"amf-1"}}}`, false},
	{"POST", "/nudm-mt/v1/" + itSupi + "/loc-info/provide-loc-info", "application/json", `{"req5gsLoc":true}`,
		"ProvideLocationInfo", `{"body":{"currentLoc":true}}`, true},
	{"GET", "/nudm-sdm/v2/" + itSupi + "/am-data", "", ``,
		"GetAmData", `{"body":{"gpsis":["msisdn-905551112233"]}}`, false},
	{"POST", "/nudm-sdm/v2/" + itSupi + "/sdm-subscriptions", "application/json",
		`{"nfInstanceId":"amf-1","callbackReference":"http://amf/cb","monitoredResourceUris":["/am-data"]}`,
		"Subscribe", `{"resourceId":"sub-1","body":{"nfInstanceId":"amf-1"}}`, true},
	{"GET", "/nudr-dr/v2/subscription-data/" + itSupi + "/authentication-data/authentication-subscription", "", ``,
		"QueryAuthSubsData", `{"body":{"authenticationMethod":"5G_AKA"}}`, false},
	{"PUT", "/nudr-dr/v2/subscription-data/" + itSupi + "/context-data/amf-3gpp-access", "application/json",
		`{"amfInstanceId":"amf-1"}`, "CreateAmfContext3gpp", `{"status":204}`, true},
	// Subscriber key material in a JSON Patch: audited, but never into the audit event.
	{"PATCH", "/nudr-dr/v2/subscription-data/" + itSupi + "/authentication-data/authentication-subscription",
		"application/json-patch+json",
		`[{"op":"replace","path":"/encPermanentKey","value":"SECRET-K"},{"op":"replace","path":"/sequenceNumber","value":{"sqn":"SECRET-SQN"}}]`,
		"ModifyAuthenticationSubscription", `{"status":204}`, true},
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
	var leaked atomic.Int64 // audit events carrying a request body's secret
	var eventsMu sync.Mutex
	var events []cgaudit.Event
	_, err = nc.Subscribe("audit.test", func(m *gnats.Msg) {
		audited.Add(1)
		if strings.Contains(string(m.Data), "SECRET") {
			leaked.Add(1)
		}
		var ev cgaudit.Event
		_ = json.Unmarshal(m.Data, &ev)
		eventsMu.Lock()
		events = append(events, ev)
		eventsMu.Unlock()
	})
	require.NoError(t, err)
	cgaudit.SetPublisher(nc, "audit.test")
	defer cgaudit.SetPublisher(nil, "")

	r := chi.NewRouter()
	handlers.NewSBIHandler(log, client, itTimeout).RegisterRoutes(r)

	// A network function that gives up after 2 s, so that a request the gateway does not
	// time out itself fails the test instead of hanging it.
	serve := func(method, path, contentType, body string) *httptest.ResponseRecorder {
		var rd io.Reader
		if body != "" {
			rd = bytes.NewBufferString(body)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		req := httptest.NewRequest(method, path, rd).WithContext(ctx)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}
	// auditedAs checks that a phase audited each state-changing call, and only those, with
	// the outcome, status and cause the network function got: refused and failed attempts
	// leave a trace too.
	var wantAudited int64
	for _, c := range itCalls {
		if c.audited {
			wantAudited++
		}
	}
	auditedAs := func(t *testing.T, before int64, outcome string, status int, cause string) {
		t.Helper()
		require.Eventually(t, func() bool { return audited.Load() == before+wantAudited }, 5*time.Second, 20*time.Millisecond)
		time.Sleep(100 * time.Millisecond) // none more
		require.Equal(t, before+wantAudited, audited.Load(), "audit events")
		eventsMu.Lock()
		defer eventsMu.Unlock()
		for _, ev := range events[before:] {
			assert.Equal(t, outcome, ev.Outcome, "%s", ev.Action)
			assert.Equal(t, status, ev.Status, "%s", ev.Action)
			assert.Equal(t, cause, ev.Cause, "%s", ev.Action)
		}
	}

	t.Run("results", func(t *testing.T) {
		replies := map[string]string{}
		for _, c := range itCalls {
			replies[c.operation] = c.reply
		}
		app, err := nc.Subscribe("5g.>", func(m *gnats.Msg) {
			var req sbiclient.Request
			_ = json.Unmarshal(m.Data, &req)
			_ = m.Respond([]byte(replies[req.Operation]))
		})
		require.NoError(t, err)
		defer func() { require.NoError(t, app.Unsubscribe()) }()
		before := audited.Load()
		for _, c := range itCalls {
			rec := serve(c.method, c.path, c.contentType, c.body)
			assert.Less(t, rec.Code, 300, "%s %s: %s", c.method, c.path, rec.Body.String())
		}
		require.Eventually(t, func() bool { return audited.Load() == before+wantAudited }, 5*time.Second, 20*time.Millisecond)
		eventsMu.Lock()
		for _, ev := range events[before:] {
			assert.Equal(t, "success", ev.Outcome, "%s", ev.Action)
			assert.Less(t, ev.Status, 300, "%s", ev.Action)
		}
		eventsMu.Unlock()
		assert.Zero(t, leaked.Load(), "audit events with key material")
	})

	t.Run("error reply", func(t *testing.T) {
		const problem = `{"status":404,"cause":"USER_NOT_FOUND","detail":"no such subscriber","invalidParams":[{"param":"/supi"}]}`
		app, err := nc.Subscribe("5g.>", func(m *gnats.Msg) { _ = m.Respond([]byte(`{"problemDetails":` + problem + `}`)) })
		require.NoError(t, err)
		defer func() { require.NoError(t, app.Unsubscribe()) }()
		before := audited.Load()
		for _, c := range itCalls {
			rec := serve(c.method, c.path, c.contentType, c.body)
			assert.Equal(t, http.StatusNotFound, rec.Code, "%s %s", c.method, c.path)
			assert.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"), "%s %s", c.method, c.path)
			assert.JSONEq(t, problem, rec.Body.String(), "%s %s", c.method, c.path)
		}
		auditedAs(t, before, "rejected", http.StatusNotFound, "USER_NOT_FOUND")
	})

	t.Run("silent application", func(t *testing.T) {
		app, err := nc.Subscribe("5g.>", func(*gnats.Msg) {})
		require.NoError(t, err)
		defer func() { require.NoError(t, app.Unsubscribe()) }()
		before := audited.Load()
		for _, c := range itCalls {
			start := time.Now()
			rec := serve(c.method, c.path, c.contentType, c.body)
			elapsed := time.Since(start)
			assertProblem(t, rec, http.StatusGatewayTimeout, "TARGET_NF_NOT_REACHABLE", c.method+" "+c.path)
			assert.GreaterOrEqual(t, elapsed, itTimeout, "%s %s", c.method, c.path)
			assert.Less(t, elapsed, 5*itTimeout, "%s %s", c.method, c.path)
		}
		auditedAs(t, before, "failed", http.StatusGatewayTimeout, "TARGET_NF_NOT_REACHABLE")
	})

	t.Run("no application", func(t *testing.T) {
		before := audited.Load()
		for _, c := range itCalls {
			start := time.Now()
			rec := serve(c.method, c.path, c.contentType, c.body)
			assertProblem(t, rec, http.StatusGatewayTimeout, "TARGET_NF_NOT_REACHABLE", c.method+" "+c.path)
			assert.Less(t, time.Since(start), itTimeout, "%s %s: no responders is known at once", c.method, c.path)
		}
		auditedAs(t, before, "failed", http.StatusGatewayTimeout, "TARGET_NF_NOT_REACHABLE")
	})

	t.Run("stream captures 5g.>", func(t *testing.T) {
		js, err := client.JetStream()
		require.NoError(t, err)
		_, err = js.CreateStream(t.Context(), jetstream.StreamConfig{Name: "CORE_EVENTS", Subjects: []string{"5g.>"}})
		require.NoError(t, err)
		before := audited.Load()
		for _, c := range itCalls {
			rec := serve(c.method, c.path, c.contentType, c.body)
			assertProblem(t, rec, http.StatusInternalServerError, "SYSTEM_FAILURE", c.method+" "+c.path)
			assert.False(t, strings.Contains(rec.Body.String(), "CORE_EVENTS"), "stream name in the problem detail")
		}
		auditedAs(t, before, "failed", http.StatusInternalServerError, "SYSTEM_FAILURE")
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
