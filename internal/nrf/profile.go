// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

// Package nrf registers the gateway with the NRF (TS 29.510 Nnrf_NFManagement): one NF
// profile per NF type it fronts (UDM, UDR, and the SMS-GMSC whose MT SMS it sends), kept
// alive by heartbeats, removed by Deregister when the installation is removed.
//
// The installation is one NF instance per profile, whatever its replica count: every pod
// registers the same profile and heartbeats it, so a pod that stops does not take the
// instance with it. A pod does not deregister on SIGTERM; it stops heartbeating.
package nrf

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers"
)

// File is NRF_PROFILES_FILE: the NF profiles the gateway registers, in TS 29.510 terms.
//
//	{"profiles": [{
//	  "profile": {"nfInstanceId": "<UUID v4>", "nfType": "UDM", "fqdn": "...", "udmInfo": {...}},
//	  "service": {"ipEndPoints": [{"port": 443}]}
//	}]}
//
// "profile" is a TS 29.510 NFProfile, registered as written, without what the gateway sets
// itself: nfStatus, heartBeatTimer (NRF_HEARTBEAT_TIMER), nfServices and nfServiceList.
// "service" holds TS 29.510 NFService attributes the gateway adds to each service it
// registers (fqdn, ipEndPoints, apiPrefix, allowedNfTypes, ...), without what it sets
// itself: serviceInstanceId, serviceName, versions, scheme, nfServiceStatus and
// oauth2Required.
type File struct {
	Profiles []FileEntry `json:"profiles"`
}

// FileEntry is one NF profile of File.
type FileEntry struct {
	Profile map[string]json.RawMessage `json:"profile"`
	Service map[string]json.RawMessage `json:"service"`
}

// Profile is one NF profile ready to register.
type Profile struct {
	InstanceID string
	Type       string // "UDM", "UDR" or "SMS_GMSC"
	// Consumer: the profile registers no service; the gateway calls other network functions
	// as this instance (the SMS_GMSC), with its access tokens.
	Consumer bool
	Body     []byte // the NFProfile the registration PUTs
	// Heartbeat is the heartbeat interval proposed at registration; 0: none proposed.
	Heartbeat time.Duration
}

// Options are what the gateway knows of itself that the profile states.
type Options struct {
	// TLS: the SBI port serves https; otherwise http (h2c).
	TLS bool
	// OAuth: the SBI port requires an access token (oauth2Required).
	OAuth bool
	// Heartbeat is the interval to propose (NRF_HEARTBEAT_TIMER); 0: none.
	Heartbeat time.Duration
}

// prefixes maps each NF type the gateway registers to the APIs a profile of that type
// offers: the UDM the Nudm APIs, the UDR the Nudr ones.
var prefixes = map[string]string{"UDM": "nudm-", "UDR": "nudr-"}

// SMSGMSC is the NF type of the consumer profile: the SMS-GMSC calls Nsmsf_SMService
// MtForwardSm (TS 29.540 Table 5.2.1-1), which the gateway does for the SMS platform. It
// offers no SBI service the gateway serves; it registers because an NRF may issue tokens to
// registered instances alone, matching the requested NF type to the profile's (TS 33.501
// clause 13.4.1.1.2; free5GC's NRF does), and a producer's allowedNfTypes name it.
const SMSGMSC = "SMS_GMSC"

// gatewayProfileAttrs and gatewayServiceAttrs are what the gateway sets: the file may not.
var (
	gatewayProfileAttrs = []string{"nfStatus", "heartBeatTimer", "nfServices", "nfServiceList"}
	gatewayServiceAttrs = []string{"serviceInstanceId", "serviceName", "versions", "scheme", "nfServiceStatus", "oauth2Required"}
)

// uuidV4 is the canonical, lower-case form of a UUID version 4 (RFC 4122), which TS 29.510
// clause 5.2.2.2.2 requires of an NF instance ID. Lower case so that the ID is the same
// string in the profile, OAUTH_AUDIENCE and the certificate's urn:uuid URI SAN.
var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// LoadFile reads and checks NRF_PROFILES_FILE and builds its profiles.
func LoadFile(path string, opts Options) ([]Profile, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- NRF_PROFILES_FILE, set by the operator, never by a request
	if err != nil {
		return nil, fmt.Errorf("NRF_PROFILES_FILE: %w", err)
	}
	profiles, err := Build(data, opts, handlers.ServedAPIs())
	if err != nil {
		return nil, fmt.Errorf("NRF_PROFILES_FILE %s: %w", path, err)
	}
	return profiles, nil
}

// Build checks the profile file's content and builds each NF profile with the services of
// apis its type offers.
func Build(data []byte, opts Options, apis []handlers.API) ([]Profile, error) {
	var f File
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("not a profile file: %w", err)
	}
	if dec.More() {
		return nil, errors.New("not a profile file: data after the JSON object")
	}
	if len(f.Profiles) == 0 {
		return nil, errors.New("no profile")
	}
	if opts.Heartbeat < 0 || opts.Heartbeat%time.Second != 0 {
		return nil, fmt.Errorf("NRF_HEARTBEAT_TIMER %s: want whole seconds", opts.Heartbeat)
	}
	seenType, seenID := map[string]bool{}, map[string]bool{}
	var out []Profile
	for i, e := range f.Profiles {
		p, err := build(e, opts, apis)
		if err != nil {
			return nil, fmt.Errorf("profile %d: %w", i, err)
		}
		if seenType[p.Type] {
			return nil, fmt.Errorf("profile %d: a second %s profile", i, p.Type)
		}
		if seenID[p.InstanceID] {
			return nil, fmt.Errorf("profile %d: nfInstanceId %s is another profile's", i, p.InstanceID)
		}
		seenType[p.Type], seenID[p.InstanceID] = true, true
		out = append(out, p)
	}
	return out, nil
}

func build(e FileEntry, opts Options, apis []handlers.API) (Profile, error) {
	if e.Profile == nil {
		return Profile{}, errors.New(`no "profile"`)
	}
	var id, nfType string
	if err := str(e.Profile, "nfInstanceId", &id); err != nil {
		return Profile{}, err
	}
	if !uuidV4.MatchString(id) {
		return Profile{}, fmt.Errorf("nfInstanceId %q: want a UUID version 4 in lower case (TS 29.510 clause 5.2.2.2.2)", id)
	}
	if err := str(e.Profile, "nfType", &nfType); err != nil {
		return Profile{}, err
	}
	prefix, ok := prefixes[nfType]
	consumer := nfType == SMSGMSC
	if !ok && !consumer {
		return Profile{}, fmt.Errorf("nfType %q: the gateway registers UDM, UDR or %s", nfType, SMSGMSC)
	}
	if consumer && e.Service != nil {
		return Profile{}, fmt.Errorf(`"service": the %s profile registers no service`, SMSGMSC)
	}
	for _, a := range gatewayProfileAttrs {
		if _, set := e.Profile[a]; set {
			return Profile{}, fmt.Errorf("%q is set by the gateway, not the file", a)
		}
	}
	for _, a := range gatewayServiceAttrs {
		if _, set := e.Service[a]; set {
			return Profile{}, fmt.Errorf(`"service": %q is set by the gateway, not the file`, a)
		}
	}
	// TS 29.510 Table 6.1.6.2.2-1 NOTE 1: at least one addressing parameter in the profile;
	// with https, an FQDN in the profile or the service (Table 6.1.6.2.3-1 NOTE 8).
	_, fqdn := e.Profile["fqdn"]
	_, v4 := e.Profile["ipv4Addresses"]
	_, v6 := e.Profile["ipv6Addresses"]
	if !fqdn && !v4 && !v6 {
		return Profile{}, errors.New("no fqdn, ipv4Addresses or ipv6Addresses (TS 29.510 Table 6.1.6.2.2-1 NOTE 1)")
	}
	if _, svcFQDN := e.Service["fqdn"]; opts.TLS && !consumer && !fqdn && !svcFQDN {
		return Profile{}, errors.New("the SBI port serves https: the profile or the service needs an fqdn (TS 29.510 Table 6.1.6.2.3-1 NOTE 8)")
	}

	scheme := "http"
	if opts.TLS {
		scheme = "https"
	}
	services := map[string]map[string]any{}
	var list []map[string]any
	for _, api := range apis {
		if !strings.HasPrefix(api.Name, prefix) {
			continue
		}
		svc := map[string]any{}
		for k, v := range e.Service {
			svc[k] = v
		}
		svc["serviceInstanceId"] = api.Name
		svc["serviceName"] = api.Name
		svc["versions"] = []map[string]string{{"apiVersionInUri": api.VersionInURI, "apiFullVersion": api.FullVersion}}
		svc["scheme"] = scheme
		svc["nfServiceStatus"] = "REGISTERED"
		svc["oauth2Required"] = opts.OAuth
		services[api.Name] = svc
		list = append(list, svc)
	}
	if len(list) == 0 && !consumer {
		return Profile{}, fmt.Errorf("the gateway serves no %s API", prefix)
	}

	body := map[string]any{}
	for k, v := range e.Profile {
		body[k] = v
	}
	body["nfStatus"] = "REGISTERED"
	// nfServiceList is the Rel-16+ form; nfServices, deprecated, is what an NRF without the
	// Service-Map feature reads (TS 29.510 clause 5.2.2.2.2 NOTE 2). Both carry the same
	// services; a consumer profile has none.
	if !consumer {
		body["nfServiceList"] = services
		body["nfServices"] = list
	}
	if opts.Heartbeat > 0 {
		body["heartBeatTimer"] = int(opts.Heartbeat / time.Second)
	}
	data, err := json.Marshal(body)
	if err != nil {
		return Profile{}, err
	}
	return Profile{InstanceID: id, Type: nfType, Consumer: consumer, Body: data, Heartbeat: opts.Heartbeat}, nil
}

// str reads a string attribute the profile must carry.
func str(m map[string]json.RawMessage, name string, out *string) error {
	raw, ok := m[name]
	if !ok {
		return fmt.Errorf("no %q", name)
	}
	if err := json.Unmarshal(raw, out); err != nil || *out == "" {
		return fmt.Errorf("%q: want a non-empty string", name)
	}
	return nil
}
