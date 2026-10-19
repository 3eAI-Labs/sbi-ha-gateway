// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	sbiclient "github.com/3eAI-Labs/sbi-ha-gateway-client"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/models"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/routectx"
	"github.com/go-chi/chi/v5"
	gnats "github.com/nats-io/nats.go"
)

// fakeNATS is the application: it records the request and answers with reply(request).
type fakeNATS struct {
	subject string
	req     sbiclient.Request
	calls   int
	reply   func(sbiclient.Request) string
	err     error
}

func (f *fakeNATS) Request(_ context.Context, subject string, data []byte, _ time.Duration) ([]byte, error) {
	f.calls++
	f.subject = subject
	f.req = sbiclient.Request{}
	if err := json.Unmarshal(data, &f.req); err != nil {
		panic(err)
	}
	if f.err != nil {
		return nil, f.err
	}
	return []byte(f.reply(f.req)), nil
}
func (f *fakeNATS) Publish(string, []byte) error { return nil }
func (f *fakeNATS) IsConnected() bool            { return true }
func (f *fakeNATS) GetConn() *gnats.Conn         { return nil }
func (f *fakeNATS) Close()                       {}

// sbiRouter is the gateway's routing with app as the application. route receives the route
// each request recorded for the access log and metrics.
func sbiRouter(app *fakeNATS, route *string) *chi.Mux {
	r := chi.NewRouter()
	r.Use(routectx.Middleware)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req)
			if route != nil {
				*route = routectx.Get(req)
			}
		})
	})
	NewSBIHandler(slog.New(slog.NewTextHandler(io.Discard, nil)), app, time.Second).RegisterRoutes(r)
	return r
}

func call(r http.Handler, method, path, contentType, body string) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "http://udm.example"+path, rd)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func problem(t *testing.T, rec *httptest.ResponseRecorder) models.ProblemDetails {
	t.Helper()
	var p models.ProblemDetails
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("Content-Type %q, want application/problem+json; body %s", ct, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("problem body: %v: %s", err, rec.Body)
	}
	return p
}

// sampleUE is a valid identifier of each kind.
var sampleUE = []struct {
	kind UeIDKinds
	id   string
}{
	{IDSUPI, "imsi-001010000000001"},
	{IDSUCI, "suci-0-001-01-0000-0-0-0001010000"},
	{IDGPSI, "msisdn-905551112233"},
	{IDExtGroup, "extgroupid-group1@example.com"},
	{IDAnyUE, "anyUE"},
}

func sample(v specVar) string {
	switch v.Kind {
	case varUE:
		for _, s := range sampleUE {
			if v.UE&s.kind != 0 {
				return s.id
			}
		}
		panic("no sample for " + v.UE.String())
	case varPduSessionID:
		return "5"
	}
	return "seg-1"
}

// fill puts a sample value for each variable of op's path.
func fill(op *specOperation) (string, map[string]string) {
	path := op.Path
	params := map[string]string{}
	for _, v := range op.Vars {
		params[v.Name] = sample(v)
		path = strings.Replace(path, "{"+v.Name+"}", params[v.Name], 1)
	}
	return path, params
}

func requestBody(op *specOperation) (string, string) {
	if len(op.Accepts) == 0 {
		return "", ""
	}
	if op.Accepts[0] == "application/json-patch+json" {
		return op.Accepts[0], `[{"op":"replace","path":"/a","value":1}]`
	}
	return op.Accepts[0], `{"a":1}`
}

// Every operation of the specification, as a network function calls it: the application
// gets it in the specification's terms on the operation's subject, and the network function
// gets the status, Location and body the application chose.
func TestSBI_EveryOperation(t *testing.T) {
	for i := range specOperations {
		op := &specOperations[i]
		t.Run(op.API+" "+op.OperationID, func(t *testing.T) {
			status := op.Success[0]
			app := &fakeNATS{reply: func(sbiclient.Request) string {
				return `{"status":` + strconv.Itoa(status) + `,"resourceId":"r 1","body":{"result":true}}`
			}}
			var route string
			path, params := fill(op)
			ct, body := requestBody(op)
			full := "/" + op.API + "/" + op.Version + path
			rec := call(sbiRouter(app, &route), op.Method, full, ct, body)

			if rec.Code != status {
				t.Fatalf("%s %s: %d %s, want %d", op.Method, full, rec.Code, rec.Body, status)
			}
			if app.req.Operation != op.OperationID || app.subject != op.subject() {
				t.Fatalf("routed to %s on %s, want %s on %s", app.req.Operation, app.subject, op.OperationID, op.subject())
			}
			want := sbiclient.Request{
				Service: op.API, Operation: op.OperationID, Method: op.Method, Path: path,
				ContentType: ct,
			}
			if len(params) > 0 {
				want.Params = params
			}
			got := app.req
			got.Body = nil
			if !equalRequest(got, want) {
				t.Errorf("request %+v, want %+v", got, want)
			}
			if body != "" && !jsonEqual(app.req.Body, []byte(body)) {
				t.Errorf("body %s, want %s", app.req.Body, body)
			}
			if route != "/"+op.API+"/"+op.Version+op.Path {
				t.Errorf("route %q", route)
			}

			loc := rec.Header().Get("Location")
			switch {
			case status == http.StatusCreated && op.Location == locRequestURI:
				if loc != "http://udm.example"+full {
					t.Errorf("Location %q", loc)
				}
			case status == http.StatusCreated && op.Location == locChild:
				if loc != "http://udm.example"+full+"/r%201" {
					t.Errorf("Location %q", loc)
				}
			default:
				if loc != "" {
					t.Errorf("Location %q on %d", loc, status)
				}
			}
			if status == http.StatusNoContent {
				if rec.Body.Len() != 0 || rec.Header().Get("Content-Type") != "" {
					t.Errorf("204 with body %q, Content-Type %q", rec.Body, rec.Header().Get("Content-Type"))
				}
			} else if rec.Header().Get("Content-Type") != "application/json" || rec.Body.String() != `{"result":true}` {
				t.Errorf("body %q, Content-Type %q", rec.Body, rec.Header().Get("Content-Type"))
			}
		})
	}
}

func equalRequest(a, b sbiclient.Request) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func jsonEqual(a, b []byte) bool {
	var x, y any
	return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && equalJSON(x, y)
}

func equalJSON(x, y any) bool {
	a, _ := json.Marshal(x)
	b, _ := json.Marshal(y)
	return bytes.Equal(a, b)
}

// findOp returns the operation of api with operationId id.
func findOp(t *testing.T, api, id string) *specOperation {
	t.Helper()
	for i := range specOperations {
		if specOperations[i].API == api && specOperations[i].OperationID == id {
			return &specOperations[i]
		}
	}
	t.Fatalf("no operation %s %s", api, id)
	return nil
}

// The API roots are TS 29.503's and TS 29.504's: Nudm_SDM and Nudr_DataRepository are v2.
func TestSBI_APIVersions(t *testing.T) {
	want := map[string]string{
		"nudm-ueau": "v1", "nudm-uecm": "v1", "nudm-sdm": "v2", "nudm-ee": "v1",
		"nudm-pp": "v1", "nudm-mt": "v1", "nudm-rsds": "v1", "nudr-dr": "v2",
	}
	got := map[string]string{}
	for _, op := range specOperations {
		got[op.API] = op.Version
	}
	if !equalJSON(got, want) {
		t.Errorf("API versions %v, want %v", got, want)
	}
}

// A reply's status must be one the operation allows; 0 stands for the only one.
func TestSBI_ReplyStatus(t *testing.T) {
	put := findOp(t, sbiclient.ServiceNudmUECM, "3GppRegistration") // 200, 201, 204
	gen := findOp(t, sbiclient.ServiceNudmUEAU, "GenerateAuthData") // 200
	supi := "imsi-001010000000001"
	reg := "/nudm-uecm/v1/" + supi + "/registrations/amf-3gpp-access"
	for _, c := range []struct {
		op         *specOperation
		path, body string
		reply      string
		want       int
	}{
		{put, reg, `{}`, `{"status":201,"body":{"amfInstanceId":"a"}}`, 201},
		{put, reg, `{}`, `{"status":200,"body":{"amfInstanceId":"a"}}`, 200},
		{put, reg, `{}`, `{"status":204}`, 204},
		{put, reg, `{}`, `{"body":{"amfInstanceId":"a"}}`, 500}, // several allowed: status required
		{put, reg, `{}`, `{"status":202,"body":{}}`, 500},
		{put, reg, `{}`, `{"status":404,"body":{}}`, 500}, // an error is an ErrorReply
		{gen, "/nudm-ueau/v1/" + supi + "/security-information/generate-auth-data", `{}`, `{"body":{"authType":"5G_AKA"}}`, 200},
		{gen, "/nudm-ueau/v1/" + supi + "/security-information/generate-auth-data", `{}`, `{"status":201,"body":{}}`, 500},
	} {
		app := &fakeNATS{reply: func(sbiclient.Request) string { return c.reply }}
		rec := call(sbiRouter(app, nil), c.op.Method, c.path, "application/json", c.body)
		if rec.Code != c.want {
			t.Errorf("%s reply %s: %d %s, want %d", c.op.OperationID, c.reply, rec.Code, rec.Body, c.want)
		}
		if c.want == 500 && problem(t, rec).Cause != "SYSTEM_FAILURE" {
			t.Errorf("%s reply %s: cause %q", c.op.OperationID, c.reply, problem(t, rec).Cause)
		}
	}
}

// A 200 or 201 carries the application's body, a JSON object or array; a 201 that creates a
// resource under the request URI needs its identifier, one path segment.
func TestSBI_ReplyBodyAndResourceId(t *testing.T) {
	confirm := "/nudm-ueau/v1/imsi-001010000000001/auth-events"
	shared := "/nudm-sdm/v2/shared-data?shared-data-ids=a,b"
	for _, c := range []struct {
		method, path, body, reply string
		want                      int
		location                  string
	}{
		{"POST", confirm, `{}`, `{"resourceId":"ev-1","body":{"success":true}}`, 201, "http://udm.example" + confirm + "/ev-1"},
		{"POST", confirm, `{}`, `{"body":{"success":true}}`, 500, ""},
		{"POST", confirm, `{}`, `{"resourceId":"a/b","body":{}}`, 500, ""},
		{"POST", confirm, `{}`, `{"resourceId":"..","body":{}}`, 500, ""},
		{"POST", confirm, `{}`, `{"resourceId":"ev-1"}`, 500, ""},
		{"GET", shared, ``, `{"body":[{"sharedDataId":"a"}]}`, 200, ""},
		{"GET", shared, ``, `{"body":null}`, 500, ""},
		{"GET", shared, ``, `{"body":"text"}`, 500, ""},
		{"GET", shared, ``, `{}`, 500, ""},
	} {
		app := &fakeNATS{reply: func(sbiclient.Request) string { return c.reply }}
		ct := ""
		if c.body != "" {
			ct = "application/json"
		}
		rec := call(sbiRouter(app, nil), c.method, c.path, ct, c.body)
		if rec.Code != c.want || rec.Header().Get("Location") != c.location {
			t.Errorf("%s %s reply %s: %d Location %q, want %d %q", c.method, c.path, c.reply,
				rec.Code, rec.Header().Get("Location"), c.want, c.location)
		}
	}
}

// The request body: a JSON object or array of a media type the operation accepts, present
// when the specification requires it, at most MaxRequestBodyBytes.
func TestSBI_RequestBody(t *testing.T) {
	reg := "/nudm-uecm/v1/imsi-001010000000001/registrations/amf-3gpp-access"
	eePatch := "/nudm-ee/v1/msisdn-905551112233/ee-subscriptions/s1"
	big := `{"a":"` + strings.Repeat("x", MaxRequestBodyBytes) + `"}`
	for _, c := range []struct {
		method, path, ct, body string
		want                   int
		cause                  string
	}{
		{"PUT", reg, "application/json", ``, 400, "INVALID_MSG_FORMAT"},
		{"PUT", reg, "application/json", `not json`, 400, "INVALID_MSG_FORMAT"},
		{"PUT", reg, "application/json", `"a string"`, 400, "INVALID_MSG_FORMAT"},
		{"PUT", reg, "application/json", `null`, 400, "INVALID_MSG_FORMAT"},
		{"PUT", reg, "text/plain", `{}`, 415, ""},
		{"PUT", reg, "", `{}`, 415, ""},
		{"PATCH", eePatch, "application/json", `[]`, 415, ""}, // EE PATCH is JSON Patch
		{"PUT", reg, "application/json", big, 413, ""},
	} {
		app := &fakeNATS{reply: func(sbiclient.Request) string { return `{"status":201,"body":{}}` }}
		rec := call(sbiRouter(app, nil), c.method, c.path, c.ct, c.body)
		if rec.Code != c.want {
			t.Errorf("%s %s %q %.40q: %d, want %d", c.method, c.path, c.ct, c.body, rec.Code, c.want)
			continue
		}
		if p := problem(t, rec); p.Cause != c.cause {
			t.Errorf("%.40q: cause %q, want %q", c.body, p.Cause, c.cause)
		}
		if app.calls != 0 {
			t.Errorf("%.40q reached the application", c.body)
		}
	}

	// A media type with parameters is that media type.
	app := &fakeNATS{reply: func(sbiclient.Request) string { return `{"status":201,"body":{}}` }}
	if rec := call(sbiRouter(app, nil), "PUT", reg, "application/json; charset=utf-8", `{}`); rec.Code != 201 ||
		app.req.ContentType != "application/json" {
		t.Errorf("Content-Type with charset: %d, %q", rec.Code, app.req.ContentType)
	}
}

// UE identifiers in the URI: each variable accepts the kinds its schema names, nothing
// else, and only URI-safe characters (TS 29.571; an escaped "/" must not shift the path).
func TestSBI_UeIdentifiers(t *testing.T) {
	const (
		supi = "imsi-001010000000001"
		gpsi = "msisdn-905551112233"
		suci = "suci-0-001-01-0000-0-0-0001010000"
	)
	for _, c := range []struct {
		method, path, body string
		want               int
		param              string
	}{
		// SDM {ueId} is a SUPI or a GPSI (B.5); {supi} a SUPI.
		{"POST", "/nudm-sdm/v2/" + gpsi + "/sdm-subscriptions", `{}`, 201, ""},
		{"GET", "/nudm-sdm/v2/" + gpsi + "/id-translation-result", ``, 200, ""},
		{"GET", "/nudm-sdm/v2/" + gpsi + "/am-data", ``, 400, "{supi}"},
		// UEAU {supiOrSuci} takes a SUCI, {supi} does not.
		{"POST", "/nudm-ueau/v1/" + suci + "/security-information/generate-auth-data", `{}`, 200, ""},
		{"POST", "/nudm-ueau/v1/" + suci + "/auth-events", `{}`, 400, "{supi}"},
		// UECM: PUT takes a SUPI (Supi), GET a SUPI or a GPSI (VarUeId).
		{"PUT", "/nudm-uecm/v1/" + gpsi + "/registrations/amf-3gpp-access", `{}`, 400, "{ueId}"},
		{"GET", "/nudm-uecm/v1/" + gpsi + "/registrations/amf-3gpp-access", ``, 200, ""},
		// Global Line and Cable Identifiers are SUPIs (B.26).
		{"PUT", "/nudm-uecm/v1/gli-line1@operator.example/registrations/amf-3gpp-access", `{}`, 201, ""},
		{"PUT", "/nudm-uecm/v1/gci-cable1/registrations/amf-3gpp-access", `{}`, 201, ""},
		// EE {ueIdentity}: a GPSI, an External Group Id or anyUE; not a SUPI.
		{"POST", "/nudm-ee/v1/anyUE/ee-subscriptions", `{}`, 201, ""},
		{"POST", "/nudm-ee/v1/" + supi + "/ee-subscriptions", `{}`, 400, "{ueIdentity}"},
		// RSDS {ueIdentity} is a GPSI or an External Group Id, as the SMS-GMSC knows the UE.
		{"POST", "/nudm-rsds/v1/" + supi + "/sm-delivery-status", `{}`, 400, "{ueIdentity}"},
		// Escaped characters are not part of any identifier.
		{"GET", "/nudm-sdm/v2/msisdn-9055%2F51112233/sdm-subscriptions/x", ``, 405, ""},
		{"GET", "/nudm-uecm/v1/extid-a%2Fb@example.com/registrations", ``, 400, "{ueId}"},
		{"GET", "/nudm-sdm/v2/imsi-001010000000001%2Fx/am-data", ``, 400, "{supi}"},
		// {pduSessionId} is an integer 0-255, as written.
		{"GET", "/nudm-uecm/v1/" + supi + "/registrations/smf-registrations/256", ``, 400, "{pduSessionId}"},
		{"GET", "/nudm-uecm/v1/" + supi + "/registrations/smf-registrations/05", ``, 400, "{pduSessionId}"},
	} {
		app := &fakeNATS{reply: func(sbiclient.Request) string {
			return `{"status":201,"resourceId":"s1","body":{}}`
		}}
		if c.method == "GET" || strings.Contains(c.path, "generate-auth-data") {
			app.reply = func(sbiclient.Request) string { return `{"body":{}}` }
		}
		ct := ""
		if c.body != "" {
			ct = "application/json"
		}
		rec := call(sbiRouter(app, nil), c.method, c.path, ct, c.body)
		if rec.Code != c.want {
			t.Errorf("%s %s: %d %s, want %d", c.method, c.path, rec.Code, rec.Body, c.want)
			continue
		}
		if c.param != "" {
			p := problem(t, rec)
			if p.Cause != "MANDATORY_IE_INCORRECT" || len(p.InvalidParams) != 1 || p.InvalidParams[0].Param != c.param {
				t.Errorf("%s %s: %+v, want MANDATORY_IE_INCORRECT on %s", c.method, c.path, p, c.param)
			}
		}
	}
}

// A path variable that is not an identifier is one segment naming nothing but itself.
func TestSBI_PathConfusion(t *testing.T) {
	const supi = "imsi-001010000000001"
	for _, path := range []string{
		"/nudm-sdm/v2/" + supi + "/sdm-subscriptions/..",
		"/nudm-sdm/v2/" + supi + "/sdm-subscriptions/.",
		"/nudm-sdm/v2/" + supi + "/sdm-subscriptions/a%2Fb",
		"/nudm-sdm/v2/" + supi + "/sdm-subscriptions/%2e%2e",
		"/nudm-ueau/v1/" + supi + "/auth-events/%2E",
	} {
		app := &fakeNATS{reply: func(sbiclient.Request) string { return `{}` }}
		method := "DELETE"
		if strings.Contains(path, "auth-events") {
			method = "PUT"
		}
		rec := call(sbiRouter(app, nil), method, path, "application/json", `{}`)
		if rec.Code != http.StatusNotFound || problem(t, rec).Cause != "RESOURCE_URI_STRUCTURE_NOT_FOUND" || app.calls != 0 {
			t.Errorf("%s %s: %d %s, calls %d", method, path, rec.Code, rec.Body, app.calls)
		}
	}
	// A segment variable is passed decoded.
	app := &fakeNATS{reply: func(sbiclient.Request) string { return `{}` }}
	if rec := call(sbiRouter(app, nil), "DELETE", "/nudm-sdm/v2/"+supi+"/sdm-subscriptions/a%20b", "", ""); rec.Code != 204 ||
		app.req.Params["subscriptionId"] != "a b" || app.req.Path != "/"+supi+"/sdm-subscriptions/a%20b" {
		t.Errorf("escaped segment: %d, params %v, path %q", rec.Code, app.req.Params, app.req.Path)
	}
}

// What matches no operation (TS 29.500 Table 5.2.7.2-1): an API or version the gateway does
// not serve is 400 INVALID_API, an unknown resource of one it serves 404
// RESOURCE_URI_STRUCTURE_NOT_FOUND, a method the resource lacks 405 with Allow.
func TestSBI_NoOperation(t *testing.T) {
	const supi = "imsi-001010000000001"
	for _, c := range []struct {
		method, path string
		want         int
		cause, allow string
	}{
		{"GET", "/nudm-sdm/v1/" + supi + "/am-data", 400, "INVALID_API", ""},
		{"GET", "/nudr-dr/v1/subscription-data/" + supi + "/authentication-data/authentication-subscription", 400, "INVALID_API", ""},
		{"GET", "/nudm-niddau/v1/x", 400, "INVALID_API", ""},
		{"GET", "/nudm-rsds/v1/msisdn-905551112233/sm-delivery-status", 405, "", "POST"},
		{"GET", "/nudm-sdm/v2/" + supi + "/no-such-data", 404, "RESOURCE_URI_STRUCTURE_NOT_FOUND", ""},
		{"GET", "/nudr-dr/v2/policy-data/ues/" + supi, 404, "RESOURCE_URI_STRUCTURE_NOT_FOUND", ""},
		{"GET", "/", 404, "", ""},
		{"DELETE", "/nudm-uecm/v1/" + supi + "/registrations/amf-3gpp-access", 405, "", "GET, PUT, PATCH"},
		{"POST", "/nudm-pp/v1/" + supi + "/pp-data", 405, "", "PATCH"},
	} {
		app := &fakeNATS{}
		rec := call(sbiRouter(app, nil), c.method, c.path, "", "")
		if rec.Code != c.want || app.calls != 0 {
			t.Errorf("%s %s: %d %s, want %d", c.method, c.path, rec.Code, rec.Body, c.want)
			continue
		}
		if p := problem(t, rec); p.Cause != c.cause {
			t.Errorf("%s %s: cause %q, want %q", c.method, c.path, p.Cause, c.cause)
		}
		// A client on the wrong version of a served API learns which one is served.
		if strings.HasPrefix(c.path, "/nudm-sdm/v1/") && !strings.Contains(problem(t, rec).Detail, "nudm-sdm is served as v2") {
			t.Errorf("%s %s: detail %q does not name the served version", c.method, c.path, problem(t, rec).Detail)
		}
		if got := strings.Join(rec.Header().Values("Allow"), ", "); got != c.allow {
			t.Errorf("%s %s: Allow %q, want %q", c.method, c.path, got, c.allow)
		}
	}
}

// An ErrorReply reaches the network function as the application wrote it; one without an
// error status, or a reply that is not a JSON object, is 500.
func TestSBI_ErrorReply(t *testing.T) {
	path := "/nudm-sdm/v2/imsi-001010000000001/am-data"
	const pd = `{"status":404,"cause":"USER_NOT_FOUND","detail":"no such subscriber"}`
	for _, c := range []struct {
		reply string
		want  int
		body  string
	}{
		{`{"problemDetails":` + pd + `}`, 404, pd},
		{`{"problemDetails":{"status":200}}`, 500, ""},
		{`[]`, 500, ""},
		{`null`, 500, ""},
		{`{"stream":"S","seq":1}`, 500, ""},
	} {
		app := &fakeNATS{reply: func(sbiclient.Request) string { return c.reply }}
		rec := call(sbiRouter(app, nil), "GET", path, "", "")
		if rec.Code != c.want {
			t.Errorf("reply %s: %d %s, want %d", c.reply, rec.Code, rec.Body, c.want)
			continue
		}
		if c.body != "" && !jsonEqual(rec.Body.Bytes(), []byte(c.body)) {
			t.Errorf("reply %s: body %s", c.reply, rec.Body)
		}
	}
}

// Subjects are permission boundaries: what returns authentication vectors goes to the
// authentication back end alone.
func TestSBI_Subjects(t *testing.T) {
	for _, c := range []struct{ api, op, subject string }{
		{sbiclient.ServiceNudmUEAU, "GenerateAuthData", sbiclient.SubjectAuthRequest},
		{sbiclient.ServiceNudmUEAU, "GenerateAv", sbiclient.SubjectAuthRequest},
		{sbiclient.ServiceNudmUEAU, "ConfirmAuth", sbiclient.SubjectAuthConfirm},
		{sbiclient.ServiceNudmUEAU, "DeleteAuth", sbiclient.SubjectAuthConfirm},
		{sbiclient.ServiceNudmUECM, "3GppRegistration", sbiclient.SubjectMobilityRegistration},
		{sbiclient.ServiceNudmUECM, "Get3GppRegistration", sbiclient.SubjectMobilityQuery},
		{sbiclient.ServiceNudmUECM, "SendRoutingInfoSm", sbiclient.SubjectMobilityQuery},
		{sbiclient.ServiceNudmMT, "QueryUeInfo", sbiclient.SubjectLocationInfo},
		{sbiclient.ServiceNudmSDM, "GetAmData", sbiclient.SubjectDataQuery},
		{sbiclient.ServiceNudmSDM, "Subscribe", sbiclient.SubjectDataUpdate},
		{sbiclient.ServiceNudrDR, "QueryAuthSubsData", sbiclient.SubjectDataQuery},
		{sbiclient.ServiceNudmRSDS, "ReportSMDeliveryStatus", sbiclient.SubjectDataUpdate},
	} {
		if got := findOp(t, c.api, c.op).subject(); got != c.subject {
			t.Errorf("%s %s: %s, want %s", c.api, c.op, got, c.subject)
		}
	}
}
