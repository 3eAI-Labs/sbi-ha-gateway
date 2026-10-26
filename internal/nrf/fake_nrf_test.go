// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nrf

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeNRF is an NRF's NFManagement nf-instances resource, as TS 29.510 clause 6.1.3.3
// describes it, with switches for the answers a test needs.
type fakeNRF struct {
	t         *testing.T
	mu        sync.Mutex
	instances map[string]map[string]any
	heartbeat int // heartBeatTimer the NRF answers with; 0: none
	calls     []string
	protos    []int

	// fail answers every request with this status while non-zero.
	fail int
	// heartbeatOK answers heartbeats with 200 and the profile instead of 204.
	heartbeatOK bool

	// oauth requires an access token it issued for every request but registration, as
	// free5GC's NRF does; issued are the tokens it accepts.
	oauth     bool
	issued    map[string]bool
	tokenReqs []url.Values
	// expiresIn is the expires_in of the tokens it issues; 0: none. A non-zero exp makes
	// them JWSs with that exp claim; else they are opaque.
	expiresIn int
	exp       int64
	// tokenFail answers token requests with this status and tokenBody while non-zero.
	tokenFail int
	tokenBody string

	// discoveries are the queries of the discovery requests; validity is the validityPeriod
	// of their answers, and discFail answers them with this status while non-zero.
	discoveries []url.Values
	validity    int
	discFail    int

	// subscriptions are those the NRF holds, by subscriptionId; subscribeReqs the bodies of
	// the creations, renewals the PATCH bodies. subFail answers subscription requests with
	// this status while non-zero; grant, when set, is the validity time the NRF assigns (it
	// accepts the one asked for otherwise); noLocation leaves out the Location header, as
	// free5GC's NRF does.
	subscriptions map[string]map[string]any
	subscribeReqs []map[string]any
	renewals      [][]map[string]any
	subFail       int
	grant         string
	noLocation    bool
}

func newFakeNRF(t *testing.T) *fakeNRF {
	return &fakeNRF{t: t, instances: map[string]map[string]any{}, heartbeat: 10, issued: map[string]bool{}, expiresIn: 3600, validity: 60,
		subscriptions: map[string]map[string]any{}}
}

// discover is the NFDiscovery search of TS 29.510 clause 5.3.2.2, filtering by target NF type
// and instance ID alone.
func (f *fakeNRF) discover(w http.ResponseWriter, r *http.Request) {
	f.calls = append(f.calls, "DISCOVER")
	q := r.URL.Query()
	f.discoveries = append(f.discoveries, q)
	if ua := r.Header.Get("User-Agent"); ua != q.Get("requester-nf-type")+"-"+q.Get("requester-nf-instance-id") {
		f.t.Errorf("discovery User-Agent %q", ua)
	}
	if f.oauth {
		if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); !ok || !f.issued[tok] {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"token is invalid"}`)
			return
		}
	}
	if f.discFail != 0 {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(f.discFail)
		_, _ = io.WriteString(w, `{"cause":"FAKE"}`)
		return
	}
	found := []map[string]any{}
	for id, p := range f.instances {
		if p["nfType"] == q.Get("target-nf-type") && (q.Get("target-nf-instance-id") == "" || id == q.Get("target-nf-instance-id")) {
			found = append(found, p)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"validityPeriod": f.validity, "nfInstances": found})
}

// token is the Access Token Request of TS 29.510 clause 5.4.2.2.
func (f *fakeNRF) token(w http.ResponseWriter, r *http.Request) {
	f.calls = append(f.calls, "TOKEN")
	if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		f.t.Errorf("token request Content-Type %q", ct)
	}
	if err := r.ParseForm(); err != nil {
		f.t.Errorf("token request: %v", err)
	}
	f.tokenReqs = append(f.tokenReqs, r.PostForm)
	if f.tokenFail != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.tokenFail)
		_, _ = io.WriteString(w, f.tokenBody)
		return
	}
	for _, k := range []string{"grant_type", "nfInstanceId", "scope"} { // Table 6.3.5.2.2-1
		if r.PostForm.Get(k) == "" {
			f.t.Errorf("token request without %s", k)
		}
	}
	id := r.PostForm.Get("nfInstanceId")
	if ua := r.Header.Get("User-Agent"); ua != r.PostForm.Get("nfType")+"-"+id {
		f.t.Errorf("token request User-Agent %q", ua)
	}
	if _, ok := f.instances[id]; !ok { // free5GC issues tokens to registered instances alone
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_client"}`)
		return
	}
	tok := "token-" + strconv.Itoa(len(f.tokenReqs))
	if f.exp != 0 {
		tok = "e30." + base64.RawURLEncoding.EncodeToString([]byte(`{"exp":`+strconv.FormatInt(f.exp, 10)+`}`)) + "." + tok
	}
	f.issued[tok] = true
	rsp := map[string]any{"access_token": tok, "token_type": "Bearer", "scope": r.PostForm.Get("scope")}
	if f.expiresIn > 0 {
		rsp["expires_in"] = f.expiresIn
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rsp)
}

const nfInstancesPath = "/nnrf-nfm/v1/nf-instances/"

const subscriptionsPath = "/nnrf-nfm/v1/subscriptions"

// subscription is NFStatusSubscribe (TS 29.510 clause 5.2.2.5) and the update and removal of
// a subscription.
func (f *fakeNRF) subscription(w http.ResponseWriter, r *http.Request, id string) {
	f.calls = append(f.calls, "SUB-"+r.Method)
	if f.oauth {
		if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); !ok || !f.issued[tok] {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"token is invalid"}`)
			return
		}
	}
	if f.subFail != 0 {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(f.subFail)
		_, _ = io.WriteString(w, `{"cause":"FAKE"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	switch {
	case r.Method == http.MethodPost && id == "":
		var s map[string]any
		if err := json.Unmarshal(body, &s); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.subscribeReqs = append(f.subscribeReqs, s)
		id = "sub-" + strconv.Itoa(len(f.subscribeReqs))
		s["subscriptionId"] = id
		if f.grant != "" {
			s["validityTime"] = f.grant
		}
		f.subscriptions[id] = s
		if !f.noLocation {
			w.Header().Set("Location", "https://nrf.example"+subscriptionsPath+"/"+id)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(s)
	case r.Method == http.MethodPatch && id != "":
		if ct := r.Header.Get("Content-Type"); ct != "application/json-patch+json" {
			f.t.Errorf("subscription PATCH Content-Type %q", ct)
		}
		var patch []map[string]any
		_ = json.Unmarshal(body, &patch)
		f.renewals = append(f.renewals, patch)
		s, ok := f.subscriptions[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if f.grant == "" {
			s["validityTime"] = patch[0]["value"]
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s["validityTime"] = f.grant
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s)
	case r.Method == http.MethodDelete && id != "":
		if _, ok := f.subscriptions[id]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(f.subscriptions, id)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (f *fakeNRF) subscriptionCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.subscriptions)
}

func (f *fakeNRF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/oauth2/token" && r.Method == http.MethodPost {
		f.token(w, r)
		return
	}
	if r.URL.Path == "/nnrf-disc/v1/nf-instances" && r.Method == http.MethodGet {
		f.discover(w, r)
		return
	}
	if rest, ok := strings.CutPrefix(r.URL.Path, subscriptionsPath); ok && (rest == "" || strings.HasPrefix(rest, "/")) {
		f.subscription(w, r, strings.TrimPrefix(rest, "/"))
		return
	}
	id, ok := strings.CutPrefix(r.URL.Path, nfInstancesPath)
	if !ok || id == "" {
		f.t.Errorf("request to %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	f.calls = append(f.calls, r.Method)
	f.protos = append(f.protos, r.ProtoMajor)
	if ua := r.Header.Get("User-Agent"); ua != "UDM-"+id && ua != "UDR-"+id && ua != "SMS_GMSC-"+id {
		f.t.Errorf("%s User-Agent %q (TS 29.500 clause 5.2.2.2)", r.Method, ua)
	}
	if f.oauth && r.Method != http.MethodPut {
		if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); !ok || !f.issued[tok] {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"token is invalid"}`) // free5GC's answer
			return
		}
	}
	if f.fail != 0 {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(f.fail)
		_, _ = io.WriteString(w, `{"status":`+http.StatusText(f.fail)+`}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	switch r.Method {
	case http.MethodPut:
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			f.t.Errorf("PUT Content-Type %q", ct)
		}
		var p map[string]any
		if err := json.Unmarshal(body, &p); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if p["nfInstanceId"] != id {
			f.t.Errorf("PUT %s carries nfInstanceId %v", id, p["nfInstanceId"])
		}
		if f.heartbeat > 0 {
			p["heartBeatTimer"] = f.heartbeat
		} else {
			delete(p, "heartBeatTimer")
		}
		status := http.StatusOK
		if _, exists := f.instances[id]; !exists {
			status = http.StatusCreated
			w.Header().Set("Location", nfInstancesPath+id)
		}
		f.instances[id] = p
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(p)
	case http.MethodPatch:
		if ct := r.Header.Get("Content-Type"); ct != "application/json-patch+json" {
			f.t.Errorf("PATCH Content-Type %q", ct)
		}
		if r.Header.Get("If-Match") != "" {
			f.t.Errorf("heartbeat with If-Match (TS 29.510 clause 5.2.2.3.2 forbids it)")
		}
		var patch []map[string]any
		if err := json.Unmarshal(body, &patch); err != nil || len(patch) != 1 ||
			patch[0]["op"] != "replace" || patch[0]["path"] != "/nfStatus" || patch[0]["value"] != "REGISTERED" {
			f.t.Errorf("heartbeat body %s", body)
		}
		p, exists := f.instances[id]
		if !exists {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if f.heartbeatOK {
			p["heartBeatTimer"] = f.heartbeat
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(p)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodGet:
		p, exists := f.instances[id]
		if !exists {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(p)
	case http.MethodDelete:
		if _, exists := f.instances[id]; !exists {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(f.instances, id)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (f *fakeNRF) set(fn func(f *fakeNRF)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeNRF) callLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeNRF) registered(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.instances[id]
	return ok
}

// start serves f over HTTP/2 with TLS and returns a client of it.
func (f *fakeNRF) start(t *testing.T) *Client {
	t.Helper()
	srv := httptest.NewUnstartedServer(f)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	return c
}
