// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nrf

import (
	"context"
	"testing"
	"time"

	"github.com/free5gc/openapi/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const smsfID = "6b2f9c1e-4d3a-4f7b-8e5c-2a9d1f0b3c4e"

// smsfProfile is an SMSF's NFProfile as the NRF holds it, offering nsmsf-sms v2 at
// https://smsf.example:8443/sms.
func smsfProfile() map[string]any {
	return map[string]any{
		"nfInstanceId": smsfID, "nfType": "SMSF", "nfStatus": "REGISTERED", "fqdn": "smsf.example",
		"nfServices": []any{map[string]any{
			"serviceInstanceId": "sms", "serviceName": "nsmsf-sms", "scheme": "https", "nfServiceStatus": "REGISTERED",
			"versions":    []any{map[string]any{"apiVersionInUri": "v2", "apiFullVersion": "2.2.0"}},
			"ipEndPoints": []any{map[string]any{"ipv4Address": "192.0.2.7", "port": 8443}},
			"apiPrefix":   "/sms",
		}},
	}
}

// gmscDiscovery is discovery from nrf as a registered SMS_GMSC instance.
func gmscDiscovery(t *testing.T, nrf *fakeNRF, c *Client) (*Discovery, *clock) {
	t.Helper()
	ps, err := Build([]byte(`{"profiles": [{"profile": {"nfInstanceId": "`+gmscID+`", "nfType": "SMS_GMSC", "fqdn": "gmsc.example"}}]}`),
		Options{TLS: true}, testAPIs)
	require.NoError(t, err)
	_, err = c.Register(context.Background(), ps[0])
	require.NoError(t, err)
	d := c.Discovery(ps[0])
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	d.now = clk.now
	return d, clk
}

func smsfRoot(d *Discovery) (string, error) {
	return d.ServiceRoot(context.Background(), "SMSF", smsfID, "nsmsf-sms", "v2")
}

// The search names the SMSF instance, its service and the requester; the API root is the
// service's FQDN, its endpoint's port and its prefix.
func TestDiscovery_ServiceRoot(t *testing.T) {
	nrf := newFakeNRF(t)
	c := nrf.start(t)
	d, _ := gmscDiscovery(t, nrf, c)
	nrf.set(func(f *fakeNRF) { f.instances[smsfID] = smsfProfile() })

	root, err := smsfRoot(d)
	require.NoError(t, err)
	assert.Equal(t, "https://smsf.example:8443/sms", root)
	require.Len(t, nrf.discoveries, 1)
	q := nrf.discoveries[0]
	assert.Equal(t, "SMSF", q.Get("target-nf-type"))
	assert.Equal(t, smsfID, q.Get("target-nf-instance-id"))
	assert.Equal(t, "nsmsf-sms", q.Get("service-names"))
	assert.Equal(t, "SMS_GMSC", q.Get("requester-nf-type"))
	assert.Equal(t, gmscID, q.Get("requester-nf-instance-id"))
}

// A result serves for its validityPeriod; then the NRF is asked again.
func TestDiscovery_Validity(t *testing.T) {
	nrf := newFakeNRF(t)
	c := nrf.start(t)
	d, clk := gmscDiscovery(t, nrf, c)
	nrf.set(func(f *fakeNRF) { f.instances[smsfID] = smsfProfile() })

	for range 2 {
		_, err := smsfRoot(d)
		require.NoError(t, err)
	}
	assert.Len(t, nrf.discoveries, 1, "cached")
	clk.t = clk.t.Add(61 * time.Second)
	_, err := smsfRoot(d)
	require.NoError(t, err)
	assert.Len(t, nrf.discoveries, 2, "asked again after validityPeriod")
}

// After its validityPeriod a result still serves while the NRF cannot answer, not when it
// refuses the search or no longer knows the SMSF.
func TestDiscovery_StaleWhileNRFFails(t *testing.T) {
	nrf := newFakeNRF(t)
	c := nrf.start(t)
	d, clk := gmscDiscovery(t, nrf, c)
	nrf.set(func(f *fakeNRF) { f.instances[smsfID] = smsfProfile() })
	_, err := smsfRoot(d)
	require.NoError(t, err)

	clk.t = clk.t.Add(61 * time.Second)
	nrf.set(func(f *fakeNRF) { f.discFail = 503 })
	root, err := smsfRoot(d)
	require.NoError(t, err)
	assert.Equal(t, "https://smsf.example:8443/sms", root)

	nrf.set(func(f *fakeNRF) { f.discFail = 400 })
	_, err = smsfRoot(d)
	var se *StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, 400, se.Status)
	assert.False(t, Transient(err))

	nrf.set(func(f *fakeNRF) { f.discFail = 0; delete(f.instances, smsfID) })
	_, err = smsfRoot(d)
	require.ErrorIs(t, err, ErrNotDiscovered)
	nrf.set(func(f *fakeNRF) { f.discFail = 503 })
	_, err = smsfRoot(d)
	assert.True(t, Transient(err), "forgotten: nothing stale to serve")
}

// An unknown instance is ErrNotDiscovered, not transient; an NRF that does not answer is.
func TestDiscovery_NotFound(t *testing.T) {
	nrf := newFakeNRF(t)
	c := nrf.start(t)
	d, _ := gmscDiscovery(t, nrf, c)
	_, err := smsfRoot(d)
	require.ErrorIs(t, err, ErrNotDiscovered)
	assert.False(t, Transient(err))
	nrf.set(func(f *fakeNRF) { f.discFail = 404 })
	_, err = smsfRoot(d)
	require.ErrorIs(t, err, ErrNotDiscovered)
	nrf.set(func(f *fakeNRF) { f.discFail = 429 })
	_, err = smsfRoot(d)
	assert.True(t, Transient(err))
}

// An NRF that asks for a token gets one of scope nnrf-disc, the SMS-GMSC's.
func TestDiscovery_TokenOnDemand(t *testing.T) {
	nrf := newFakeNRF(t)
	nrf.oauth = true
	c := nrf.start(t)
	d, clk := gmscDiscovery(t, nrf, c)
	nrf.set(func(f *fakeNRF) { f.instances[smsfID] = smsfProfile() })

	_, err := smsfRoot(d)
	require.NoError(t, err)
	clk.t = clk.t.Add(61 * time.Second)
	_, err = smsfRoot(d)
	require.NoError(t, err)
	assert.Equal(t, []string{"PUT", "DISCOVER", "TOKEN", "DISCOVER", "DISCOVER"}, nrf.callLog())
	require.Len(t, nrf.tokenReqs, 1)
	assert.Equal(t, "nnrf-disc", nrf.tokenReqs[0].Get("scope"))
	assert.Equal(t, "SMS_GMSC", nrf.tokenReqs[0].Get("nfType"))
	assert.Equal(t, "NRF", nrf.tokenReqs[0].Get("targetNfType"))
}

func TestServiceRoot_Selection(t *testing.T) {
	k := discoveryKey{"SMSF", smsfID, "nsmsf-sms", "v2"}
	v2 := []models.Nrf_NFMgmt_NFServiceVersion{{ApiVersionInUri: "v2"}}
	svc := func(mod func(*models.Nrf_NFDisc_NFService)) models.Nrf_NFDisc_NFService {
		s := models.Nrf_NFDisc_NFService{ServiceInstanceId: "a", ServiceName: "nsmsf-sms", Scheme: "https",
			NfServiceStatus: models.Nrf_NFMgmt_NFServiceStatus_REGISTERED, Versions: v2}
		if mod != nil {
			mod(&s)
		}
		return s
	}
	profile := func(mod func(*models.Nrf_NFDisc_NFProfile), services ...models.Nrf_NFDisc_NFService) []models.Nrf_NFDisc_NFProfile {
		p := models.Nrf_NFDisc_NFProfile{NfInstanceId: smsfID, NfType: "SMSF", NfStatus: models.Nrf_NFMgmt_NFStatus_REGISTERED,
			Fqdn: "smsf.example", NfServices: services}
		if mod != nil {
			mod(&p)
		}
		return []models.Nrf_NFDisc_NFProfile{p}
	}
	for _, tc := range []struct {
		name     string
		profiles []models.Nrf_NFDisc_NFProfile
		want     string // "": none usable
	}{
		{"profile FQDN, default port", profile(nil, svc(nil)), "https://smsf.example"},
		{"service FQDN first", profile(nil, svc(func(s *models.Nrf_NFDisc_NFService) { s.Fqdn = "sms.smsf.example" })), "https://sms.smsf.example"},
		{"https without FQDN", profile(func(p *models.Nrf_NFDisc_NFProfile) { p.Fqdn = "" }, svc(nil)), ""},
		{"http: the endpoint before the FQDN", profile(nil, svc(func(s *models.Nrf_NFDisc_NFService) {
			s.Scheme = "http"
			s.IpEndPoints = []models.Nrf_NFMgmt_IpEndPoint{{Ipv6Address: "2001:db8::7", Port: 8080}}
		})), "http://[2001:db8::7]:8080"},
		{"http: the profile's address", profile(func(p *models.Nrf_NFDisc_NFProfile) {
			p.Fqdn, p.Ipv4Addresses = "", []string{"192.0.2.9"}
		}, svc(func(s *models.Nrf_NFDisc_NFService) { s.Scheme = "http" })), "http://192.0.2.9"},
		{"nfServiceList", profile(func(p *models.Nrf_NFDisc_NFProfile) {
			p.NfServiceList = map[string]models.Nrf_NFDisc_NFService{"a": svc(nil)}
		}), "https://smsf.example"},
		{"lowest priority", profile(nil,
			svc(func(s *models.Nrf_NFDisc_NFService) { s.Priority, s.Fqdn = 2, "low.example" }),
			svc(func(s *models.Nrf_NFDisc_NFService) { s.ServiceInstanceId, s.Priority, s.Fqdn = "b", 1, "high.example" })),
			"https://high.example"},
		{"other version", profile(nil, svc(func(s *models.Nrf_NFDisc_NFService) {
			s.Versions = []models.Nrf_NFMgmt_NFServiceVersion{{ApiVersionInUri: "v1"}}
		})), ""},
		{"service suspended", profile(nil, svc(func(s *models.Nrf_NFDisc_NFService) { s.NfServiceStatus = "SUSPENDED" })), ""},
		{"instance suspended", profile(func(p *models.Nrf_NFDisc_NFProfile) { p.NfStatus = "SUSPENDED" }, svc(nil)), ""},
		{"another instance", profile(func(p *models.Nrf_NFDisc_NFProfile) { p.NfInstanceId = gmscID }, svc(nil)), ""},
		{"prefix with a query", profile(nil, svc(func(s *models.Nrf_NFDisc_NFService) { s.ApiPrefix = "/x?y" })), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, ok := serviceRoot(tc.profiles, k)
			assert.Equal(t, tc.want, root)
			assert.Equal(t, tc.want != "", ok)
		})
	}
}

// Of the services with the lowest priority, those with capacity 0 lose to one with capacity.
func TestServiceRoot_Capacity(t *testing.T) {
	k := discoveryKey{"SMSF", smsfID, "nsmsf-sms", "v2"}
	s := func(id, fqdn string, capacity int32) models.Nrf_NFDisc_NFService {
		return models.Nrf_NFDisc_NFService{ServiceInstanceId: id, ServiceName: "nsmsf-sms", Scheme: "https", Fqdn: fqdn,
			NfServiceStatus: models.Nrf_NFMgmt_NFServiceStatus_REGISTERED, Capacity: capacity,
			Versions: []models.Nrf_NFMgmt_NFServiceVersion{{ApiVersionInUri: "v2"}}}
	}
	profiles := []models.Nrf_NFDisc_NFProfile{{NfInstanceId: smsfID, NfType: "SMSF", NfStatus: models.Nrf_NFMgmt_NFStatus_REGISTERED,
		NfServices: []models.Nrf_NFDisc_NFService{s("a", "a.example", 0), s("b", "b.example", 100)}}}
	for range 20 {
		root, ok := serviceRoot(profiles, k)
		require.True(t, ok)
		assert.Equal(t, "https://b.example", root)
	}
}
