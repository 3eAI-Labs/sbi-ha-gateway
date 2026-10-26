// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nrf

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/nrf/NFDisc"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
)

// scopeNFDiscovery is the scope of the Nnrf_NFDiscovery API (TS 29.510 clause 6.2, the
// securitySchemes of its OpenAPI).
const scopeNFDiscovery = "nnrf-disc"

// ErrNotDiscovered: the NRF knows no registered instance with that ID offering the service in
// that version.
var ErrNotDiscovered = errors.New("nrf discover: no such producer")

// Transient reports whether a discovery error may pass: the NRF did not answer, answered 5xx
// or 429, or asked for an access token it gave none for.
func Transient(err error) bool {
	if errors.Is(err, ErrNotDiscovered) {
		return false
	}
	var se *StatusError
	if errors.As(err, &se) {
		return se.Status >= 500 || se.Status == http.StatusTooManyRequests
	}
	return true
}

// Discovery finds producers' services with the NRF's Nnrf_NFDiscovery API (TS 29.510 clause
// 5.3.2.2), through free5GC's generated client, as one requester profile. The API admits
// requests with and without an access token of scope nnrf-disc (its OpenAPI's security), so
// the NRF decides, as for NFManagement: once it answers 401, every request carries one.
type Discovery struct {
	client    *Client
	apiRoot   string // the NRF's; free5GC's client adds /nnrf-disc/v1
	tokens    *tokens
	requester Profile
	oauth     atomic.Bool // the NRF answered 401
	now       func() time.Time

	mu    sync.Mutex
	found map[discoveryKey]discovered // only instances the NRF knows: it grows with them
	watch *Watcher                    // subscribes to the instances found; nil: none
}

type discoveryKey struct{ nfType, instance, service, version string }

type discovered struct {
	result []models.Nrf_NFDisc_NFProfile
	until  time.Time
}

// Discovery returns discovery from this client's NRF, as requester (its NF type and instance
// ID are the requester's in each search, and its tokens are asked for as that instance).
func (c *Client) Discovery(requester Profile) *Discovery {
	return &Discovery{
		client:    c,
		apiRoot:   c.root,
		tokens:    c.tokens,
		requester: requester,
		now:       time.Now,
		found:     map[discoveryKey]discovered{},
	}
}

// ServiceRoot returns an {apiRoot} (TS 29.501 clause 4.4.1) of the service (e.g. nsmsf-sms,
// with version e.g. v2 in its URIs) of the NF instance of type nfType with that ID. A result
// serves for the validityPeriod the NRF answers with (TS 29.510 clause 6.2.6.2.3), and after
// it while the NRF cannot be asked (Transient): an instance's address rarely moves, and the
// calls would otherwise wait for the NRF. An answer without the instance, or with no usable
// service, is ErrNotDiscovered and forgets it.
func (d *Discovery) ServiceRoot(ctx context.Context, nfType, instanceID, service, version string) (string, error) {
	k := discoveryKey{nfType, instanceID, service, version}
	d.mu.Lock()
	f, cached := d.found[k]
	d.mu.Unlock()
	if !cached || !d.now().Before(f.until) {
		result, validity, err := d.search(ctx, k)
		switch {
		case err == nil:
			f = discovered{result, d.now().Add(validity)}
		case !cached || !Transient(err):
			if errors.Is(err, ErrNotDiscovered) {
				d.forget(k)
			}
			return "", err
		}
	}
	root, ok := serviceRoot(f.result, k)
	if !ok {
		d.forget(k)
		return "", ErrNotDiscovered
	}
	d.mu.Lock()
	d.found[k] = f
	w := d.watch
	d.mu.Unlock()
	if w != nil {
		w.watch(k.nfType, k.instance)
	}
	return root, nil
}

// forget drops k's result, and the subscription to its instance once no result of the
// instance is left.
func (d *Discovery) forget(k discoveryKey) {
	d.mu.Lock()
	delete(d.found, k)
	left := false
	for o := range d.found {
		left = left || o.instance == k.instance
	}
	w := d.watch
	d.mu.Unlock()
	if w != nil && !left {
		w.unwatch(k.instance)
	}
}

// forgetInstance drops every result of the instance, and the subscription to it: the NRF
// notified its deregistration.
func (d *Discovery) forgetInstance(instanceID string) {
	d.mu.Lock()
	for k := range d.found {
		if k.instance == instanceID {
			delete(d.found, k)
		}
	}
	w := d.watch
	d.mu.Unlock()
	if w != nil {
		w.unwatch(instanceID)
	}
}

// expireInstance ends the validity of every result of the instance: the NRF notified a change
// of its profile. The next call asks the NRF; while the NRF cannot be asked, the results
// serve on, as any expired result does.
func (d *Discovery) expireInstance(instanceID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, f := range d.found {
		if k.instance == instanceID {
			f.until = time.Time{}
			d.found[k] = f
		}
	}
}

// Unknown reports whether err, from ServiceRoot, is ErrNotDiscovered.
func (*Discovery) Unknown(err error) bool { return errors.Is(err, ErrNotDiscovered) }

// Transient reports whether err, from ServiceRoot, may pass (the package's Transient).
func (*Discovery) Transient(err error) bool { return Transient(err) }

// search asks the NRF, with an access token once it asked for one. A 401 is answered with a
// fresh token, once.
func (d *Discovery) search(ctx context.Context, k discoveryKey) ([]models.Nrf_NFDisc_NFProfile, time.Duration, error) {
	var token string
	var tokenErr error
	if d.oauth.Load() {
		// Without one the request still goes: the NRF may no longer ask for it.
		token, tokenErr = d.tokens.get(ctx, d.requester, scopeNFDiscovery, nfTypeNRF, "")
	}
	result, validity, err := d.send(ctx, k, token)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusUnauthorized {
		return result, validity, err
	}
	d.oauth.Store(true)
	if tokenErr == nil {
		if token != "" {
			d.tokens.drop(d.requester, scopeNFDiscovery, nfTypeNRF, "", token)
		}
		if token, tokenErr = d.tokens.get(ctx, d.requester, scopeNFDiscovery, nfTypeNRF, ""); tokenErr == nil {
			return d.send(ctx, k, token)
		}
	}
	return nil, 0, fmt.Errorf("nrf discover: HTTP 401, and no %w", tokenErr)
}

func (d *Discovery) send(ctx context.Context, k discoveryKey, token string) ([]models.Nrf_NFDisc_NFProfile, time.Duration, error) {
	status := 0 // the answer's, even when free5GC's client cannot decode its body
	cfg := NFDisc.NewConfiguration()
	cfg.SetBasePath(d.apiRoot)
	cfg.SetHTTPClient(d.tokens.http)
	cfg.SetUserAgent(userAgent(d.requester))
	cfg.SetMetrics(func(_, _ string, s int, _ float64) { status = s })
	req := &NFDisc.SearchNFInstancesRequest{}
	req.SetTargetNfType(models.Nrf_NFMgmt_NFType(k.nfType))
	req.SetRequesterNfType(models.Nrf_NFMgmt_NFType(d.requester.Type))
	req.SetRequesterNfInstanceId(d.requester.InstanceID)
	req.SetTargetNfInstanceId(k.instance)
	req.SetServiceNames([]models.Nrf_NFMgmt_ServiceName{models.Nrf_NFMgmt_ServiceName(k.service)})
	if token != "" {
		ctx = context.WithValue(ctx, openapi.ContextAccessToken, token)
	}
	rsp, err := NFDisc.NewAPIClient(cfg).NFInstancesStoreApi.SearchNFInstances(ctx, req)
	if err == nil && rsp.Nrf_NFDisc_SearchResult == nil {
		err = errors.New("the answer carries no SearchResult")
	}
	result := "error"
	if status != 0 {
		result = strconv.Itoa(status)
	}
	metrics.RecordNRFRequest(d.requester.Type, "discover", result, err == nil)
	switch {
	case status == http.StatusNotFound:
		return nil, 0, ErrNotDiscovered
	case err != nil && status >= 300:
		var ae openapi.GenericOpenAPIError
		body := ""
		if errors.As(err, &ae) {
			body = string(ae.RawBody)
		}
		return nil, 0, response{status: status, body: []byte(body)}.err("discover")
	case err != nil:
		return nil, 0, fmt.Errorf("nrf discover: %w", err)
	}
	r := rsp.Nrf_NFDisc_SearchResult
	return r.NfInstances, time.Duration(max(r.ValidityPeriod, 0)) * time.Second, nil
}

// serviceRoot picks, among the services named in k of the registered instance k names that
// have k's version in their URIs and are registered, one of those with the lowest priority,
// at random weighted by capacity (TS 29.510 clause 6.1.6.2.3 NOTE 2: as the priority and
// weight of IETF RFC 2782), and returns its {apiRoot}.
func serviceRoot(profiles []models.Nrf_NFDisc_NFProfile, k discoveryKey) (string, bool) {
	type candidate struct {
		root               string
		priority, capacity int32
	}
	var cs []candidate
	for _, p := range profiles {
		if p.NfInstanceId != k.instance || string(p.NfType) != k.nfType || p.NfStatus != models.Nrf_NFMgmt_NFStatus_REGISTERED {
			continue
		}
		services := slices.Clone(p.NfServices)
		for _, id := range slices.Sorted(maps.Keys(p.NfServiceList)) {
			services = append(services, p.NfServiceList[id])
		}
		seen := map[string]bool{}
		for _, s := range services {
			if string(s.ServiceName) != k.service || s.NfServiceStatus != models.Nrf_NFMgmt_NFServiceStatus_REGISTERED ||
				seen[s.ServiceInstanceId] || !slices.ContainsFunc(s.Versions, func(v models.Nrf_NFMgmt_NFServiceVersion) bool {
				return v.ApiVersionInUri == k.version
			}) {
				continue
			}
			seen[s.ServiceInstanceId] = true
			if root, ok := apiRoot(p, s); ok {
				cs = append(cs, candidate{root, s.Priority, s.Capacity})
			}
		}
	}
	if len(cs) == 0 {
		return "", false
	}
	best := slices.MinFunc(cs, func(a, b candidate) int { return cmp.Compare(a.priority, b.priority) }).priority
	cs = slices.DeleteFunc(cs, func(c candidate) bool { return c.priority != best })
	var total int
	for _, c := range cs {
		total += int(max(c.capacity, 0))
	}
	if total == 0 {
		return cs[rand.IntN(len(cs))].root, true // #nosec G404 -- load spreading, not a secret
	}
	n := rand.IntN(total) // #nosec G404 -- load spreading, not a secret
	for _, c := range cs {
		if n -= int(max(c.capacity, 0)); n < 0 {
			return c.root, true
		}
	}
	return cs[len(cs)-1].root, true
}

// apiRoot builds a service's {apiRoot} as TS 29.510 clause 6.1.6.2.3 says the consumer does
// (NOTE 1, NOTE 8, ipEndPoints): over https the FQDN of the service, else of the profile; over
// http an address of the service's ipEndPoints, chosen at random (NOTE 7), which has
// precedence over the profile's addresses and FQDN, else the FQDNs, else an address of the
// profile. The port is the endpoint's; with an FQDN, that of the first endpoint giving one
// (the gateway's reading: the FQDN names the endpoints' addresses); else the scheme's
// default (clause 6.1.6.2.5 NOTE 2).
func apiRoot(p models.Nrf_NFDisc_NFProfile, s models.Nrf_NFDisc_NFService) (string, bool) {
	scheme := string(s.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", false
	}
	fqdn := cmp.Or(s.Fqdn, p.Fqdn)
	var port int32
	for _, ep := range s.IpEndPoints {
		if ep.Port > 0 {
			port = ep.Port
			break
		}
	}
	addressed := slices.DeleteFunc(slices.Clone(s.IpEndPoints), func(ep models.Nrf_NFMgmt_IpEndPoint) bool {
		return ep.Ipv4Address == "" && ep.Ipv6Address == ""
	})
	var host string
	switch {
	case scheme == "https" || fqdn != "" && len(addressed) == 0:
		host = fqdn
	case len(addressed) > 0:
		ep := addressed[rand.IntN(len(addressed))] // #nosec G404 -- load spreading, not a secret
		host, port = cmp.Or(ep.Ipv4Address, ep.Ipv6Address), ep.Port
	case len(p.Ipv4Addresses) > 0:
		host = p.Ipv4Addresses[0]
	case len(p.Ipv6Addresses) > 0:
		host = p.Ipv6Addresses[0]
	}
	if host == "" {
		return "", false
	}
	authority := host
	if port > 0 {
		authority = net.JoinHostPort(host, strconv.Itoa(int(port)))
	} else if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	root := scheme + "://" + authority
	if prefix := strings.Trim(s.ApiPrefix, "/"); prefix != "" {
		root += "/" + prefix
	}
	if u, err := url.Parse(root); err != nil || u.Host != authority || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	return root, true
}
