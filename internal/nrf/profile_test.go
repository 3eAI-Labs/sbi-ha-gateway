// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nrf

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers"
)

const (
	udmID  = "4947a69a-f61b-4bc1-b9da-47c9c5d14b64"
	udrID  = "8f2c3a1e-5b7d-4e9f-a1c3-2d4e6f8a0b1c"
	gmscID = "1d5e8b2a-7c4f-4a6e-9b3d-5f1a2c8e4d7b"
)

var testAPIs = []handlers.API{
	{Name: "nudm-ueau", VersionInURI: "v1", FullVersion: "1.2.2"},
	{Name: "nudm-sdm", VersionInURI: "v2", FullVersion: "2.2.12"},
	{Name: "nudr-dr", VersionInURI: "v2", FullVersion: "2.2.12"},
}

const twoProfiles = `{"profiles": [
  {"profile": {"nfInstanceId": "` + udmID + `", "nfType": "UDM", "fqdn": "udm.example",
               "plmnList": [{"mcc": "001", "mnc": "01"}],
               "udmInfo": {"groupId": "udm-1", "supiRanges": [{"pattern": "^imsi-00101[0-9]{10}$"}]},
               "priority": 1},
   "service": {"ipEndPoints": [{"port": 8443}], "allowedNfTypes": ["AMF", "AUSF"]}},
  {"profile": {"nfInstanceId": "` + udrID + `", "nfType": "UDR", "fqdn": "udr.example"}}
]}`

func decode(t *testing.T, p Profile) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(p.Body, &m))
	return m
}

func TestBuild_Profiles(t *testing.T) {
	ps, err := Build([]byte(twoProfiles), Options{TLS: true, OAuth: true, Heartbeat: 30 * time.Second}, testAPIs)
	require.NoError(t, err)
	require.Len(t, ps, 2)

	udm := decode(t, ps[0])
	assert.Equal(t, "UDM", ps[0].Type)
	assert.Equal(t, udmID, ps[0].InstanceID)
	assert.Equal(t, 30*time.Second, ps[0].Heartbeat)
	// The file's attributes as written, the gateway's added.
	assert.Equal(t, udmID, udm["nfInstanceId"])
	assert.Equal(t, "udm.example", udm["fqdn"])
	assert.Equal(t, float64(1), udm["priority"])
	assert.Equal(t, map[string]any{"groupId": "udm-1", "supiRanges": []any{map[string]any{"pattern": "^imsi-00101[0-9]{10}$"}}}, udm["udmInfo"])
	assert.Equal(t, "REGISTERED", udm["nfStatus"])
	assert.Equal(t, float64(30), udm["heartBeatTimer"])

	list := udm["nfServiceList"].(map[string]any)
	assert.Len(t, list, 2, "the UDM offers the nudm APIs, not nudr")
	sdm := list["nudm-sdm"].(map[string]any)
	assert.Equal(t, "nudm-sdm", sdm["serviceInstanceId"])
	assert.Equal(t, "nudm-sdm", sdm["serviceName"])
	assert.Equal(t, []any{map[string]any{"apiVersionInUri": "v2", "apiFullVersion": "2.2.12"}}, sdm["versions"])
	assert.Equal(t, "https", sdm["scheme"])
	assert.Equal(t, "REGISTERED", sdm["nfServiceStatus"])
	assert.Equal(t, true, sdm["oauth2Required"])
	assert.Equal(t, []any{map[string]any{"port": float64(8443)}}, sdm["ipEndPoints"])
	assert.Equal(t, []any{"AMF", "AUSF"}, sdm["allowedNfTypes"])
	// The deprecated array carries the same services (TS 29.510 clause 5.2.2.2.2 NOTE 2).
	arr := udm["nfServices"].([]any)
	require.Len(t, arr, 2)
	assert.Equal(t, list["nudm-ueau"], arr[0])
	assert.Equal(t, sdm, arr[1])

	udr := decode(t, ps[1])
	udrList := udr["nfServiceList"].(map[string]any)
	assert.Len(t, udrList, 1)
	assert.Contains(t, udrList, "nudr-dr")
	assert.NotContains(t, udrList["nudr-dr"], "ipEndPoints", "the service attributes are per profile")
}

func TestBuild_PlaintextNoOAuthNoHeartbeat(t *testing.T) {
	data := `{"profiles": [{"profile": {"nfInstanceId": "` + udmID + `", "nfType": "UDM", "ipv4Addresses": ["10.0.0.1"]}}]}`
	ps, err := Build([]byte(data), Options{}, testAPIs)
	require.NoError(t, err)
	m := decode(t, ps[0])
	assert.NotContains(t, m, "heartBeatTimer", "none proposed: the NRF decides")
	svc := m["nfServiceList"].(map[string]any)["nudm-ueau"].(map[string]any)
	assert.Equal(t, "http", svc["scheme"])
	assert.Equal(t, false, svc["oauth2Required"])
}

func TestBuild_Rejects(t *testing.T) {
	entry := func(profile, service string) string {
		s := `{"profiles": [{"profile": ` + profile
		if service != "" {
			s += `, "service": ` + service
		}
		return s + `}]}`
	}
	udm := func(extra string) string {
		return `{"nfInstanceId": "` + udmID + `", "nfType": "UDM", "fqdn": "udm.example"` + extra + `}`
	}
	for name, tc := range map[string]struct {
		data string
		opts Options
		want string
	}{
		"not JSON":          {data: `{`, want: "not a profile file"},
		"unknown key":       {data: `{"profiles": [], "extra": 1}`, want: "not a profile file"},
		"trailing data":     {data: entry(udm(""), "") + ` {}`, want: "data after"},
		"no profile":        {data: `{"profiles": []}`, want: "no profile"},
		"entry without one": {data: `{"profiles": [{}]}`, want: `no "profile"`},
		"no instance ID":    {data: entry(`{"nfType": "UDM", "fqdn": "x"}`, ""), want: `no "nfInstanceId"`},
		"instance ID upper case": {data: entry(`{"nfInstanceId": "4947A69A-F61B-4BC1-B9DA-47C9C5D14B64", "nfType": "UDM", "fqdn": "x"}`, ""),
			want: "UUID version 4"},
		"instance ID v1": {data: entry(`{"nfInstanceId": "4947a69a-f61b-1bc1-b9da-47c9c5d14b64", "nfType": "UDM", "fqdn": "x"}`, ""),
			want: "UUID version 4"},
		"instance ID number": {data: entry(`{"nfInstanceId": 4, "nfType": "UDM", "fqdn": "x"}`, ""), want: "non-empty string"},
		"other NF type":      {data: entry(`{"nfInstanceId": "`+udmID+`", "nfType": "AMF", "fqdn": "x"}`, ""), want: "UDM, UDR or SMS_GMSC"},
		"SMS_GMSC service": {data: entry(`{"nfInstanceId": "`+gmscID+`", "nfType": "SMS_GMSC", "fqdn": "x"}`, `{"allowedNfTypes": ["SMSF"]}`),
			want: "registers no service"},
		"SMS_GMSC without address": {data: entry(`{"nfInstanceId": "`+gmscID+`", "nfType": "SMS_GMSC"}`, ""),
			want: "no fqdn, ipv4Addresses or ipv6Addresses"},
		"nfStatus set":       {data: entry(udm(`, "nfStatus": "SUSPENDED"`), ""), want: `"nfStatus" is set by the gateway`},
		"nfServices set":     {data: entry(udm(`, "nfServices": []`), ""), want: `"nfServices" is set by the gateway`},
		"heartBeatTimer set": {data: entry(udm(`, "heartBeatTimer": 5`), ""), want: `"heartBeatTimer" is set by the gateway`},
		"service scheme set": {data: entry(udm(""), `{"scheme": "http"}`), want: `"service": "scheme" is set by the gateway`},
		"service versions":   {data: entry(udm(""), `{"versions": []}`), want: `"service": "versions" is set by the gateway`},
		"no address": {data: entry(`{"nfInstanceId": "`+udmID+`", "nfType": "UDM"}`, ""),
			want: "no fqdn, ipv4Addresses or ipv6Addresses"},
		"https without FQDN": {data: entry(`{"nfInstanceId": "`+udmID+`", "nfType": "UDM", "ipv4Addresses": ["10.0.0.1"]}`, ""),
			opts: Options{TLS: true}, want: "needs an fqdn"},
		"two UDM profiles": {data: `{"profiles": [{"profile": ` + udm("") + `}, {"profile": {"nfInstanceId": "` + udrID + `", "nfType": "UDM", "fqdn": "x"}}]}`,
			want: "a second UDM profile"},
		"one ID twice": {data: `{"profiles": [{"profile": ` + udm("") + `}, {"profile": {"nfInstanceId": "` + udmID + `", "nfType": "UDR", "fqdn": "x"}}]}`,
			want: "is another profile's"},
		"heartbeat not whole seconds": {data: entry(udm(""), ""), opts: Options{Heartbeat: 1500 * time.Millisecond}, want: "whole seconds"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Build([]byte(tc.data), tc.opts, testAPIs)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// The SMS-GMSC's profile is the instance the gateway calls the SMSF as: registered with no
// service, and with https without an FQDN, which only services need.
func TestBuild_ConsumerProfile(t *testing.T) {
	data := `{"profiles": [{"profile": {"nfInstanceId": "` + gmscID + `", "nfType": "SMS_GMSC", "ipv4Addresses": ["10.0.0.2"]}}]}`
	ps, err := Build([]byte(data), Options{TLS: true, OAuth: true, Heartbeat: 30 * time.Second}, testAPIs)
	require.NoError(t, err)
	require.Len(t, ps, 1)
	assert.True(t, ps[0].Consumer)
	assert.Equal(t, SMSGMSC, ps[0].Type)
	assert.Equal(t, map[string]any{
		"nfInstanceId": gmscID, "nfType": "SMS_GMSC", "ipv4Addresses": []any{"10.0.0.2"},
		"nfStatus": "REGISTERED", "heartBeatTimer": float64(30),
	}, decode(t, ps[0]))
}

func TestBuild_TypeWithoutAPIs(t *testing.T) {
	data := `{"profiles": [{"profile": {"nfInstanceId": "` + udrID + `", "nfType": "UDR", "fqdn": "x"}}]}`
	_, err := Build([]byte(data), Options{}, testAPIs[:2])
	require.Error(t, err)
	assert.Contains(t, err.Error(), "serves no nudr- API")
}

// The profiles the gateway registers offer exactly the APIs it serves.
func TestBuild_ServedAPIs(t *testing.T) {
	ps, err := Build([]byte(twoProfiles), Options{TLS: true}, handlers.ServedAPIs())
	require.NoError(t, err)
	var names []string
	for _, p := range ps {
		for name, svc := range decode(t, p)["nfServiceList"].(map[string]any) {
			v := svc.(map[string]any)["versions"].([]any)[0].(map[string]any)
			assert.True(t, strings.HasPrefix(v["apiFullVersion"].(string), strings.TrimPrefix(v["apiVersionInUri"].(string), "v")+"."),
				"%s: %v", name, v)
			names = append(names, name)
		}
	}
	var served []string
	for _, a := range handlers.ServedAPIs() {
		served = append(served, a.Name)
	}
	assert.ElementsMatch(t, served, names)
}
