// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package sbi

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestParseDestinations(t *testing.T) {
	d, err := ParseDestinations(" smsf1.5gc.example , .amf.example,*.udm.example, 10.20.0.0/16, 192.0.2.7, 2001:db8::/32 ", false)
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{
		"smsf1.5gc.example": true, "SMSF1.5GC.EXAMPLE.": true, "smsf2.5gc.example": false,
		"a.amf.example": true, "amf.example": false, "x.udm.example": true, "evil.example": false,
	} {
		if got := d.nameAllowed(host); got != want {
			t.Errorf("name %s: %v, want %v", host, got, want)
		}
	}
	for _, bad := range []string{"10.0.0.0/33", "http://smsf.example", "smsf_1.example", "*.", "a..b"} {
		if _, err := ParseDestinations(bad, false); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// Loopback, link-local (cloud metadata among them), unspecified and multicast addresses are
// refused even with OUTBOUND_ALLOW_ANY, unless a CIDR or address rule lists them; any other
// address needs a rule, a name that matched one, or allow-any.
func TestDestinations_Addresses(t *testing.T) {
	listed, _ := ParseDestinations("127.0.0.1, 10.20.0.0/16", false)
	anyDest, _ := ParseDestinations("", true)
	for _, c := range []struct {
		d      *Destinations
		addr   string
		byName bool
		want   bool
	}{
		{anyDest, "127.0.0.1", false, false},
		{anyDest, "::1", false, false},
		{anyDest, "169.254.169.254", false, false},
		{anyDest, "0.0.0.0", false, false},
		{anyDest, "224.0.0.1", false, false},
		{anyDest, "fe80::1", false, false},
		{anyDest, "198.51.100.9", false, true},
		{listed, "127.0.0.1", false, true},
		{listed, "::ffff:127.0.0.1", false, true},
		{listed, "10.20.3.4", false, true},
		{listed, "10.21.3.4", false, false},
		{listed, "10.21.3.4", true, true},
		{listed, "169.254.169.254", true, false},
	} {
		if got := c.d.addrAllowed(netip.MustParseAddr(c.addr), c.byName); got != c.want {
			t.Errorf("%s (by name %v, allow-any %v): %v, want %v", c.addr, c.byName, c.d.allowAny, got, c.want)
		}
	}
}

// The check runs on the connection: a destination outside the policy is never dialled, and
// the error says why.
func TestDestinations_Dial(t *testing.T) {
	var s seen
	srv := h2cServer(t, s.handler())
	port := srv.URL[strings.LastIndex(srv.URL, ":"):]
	for _, c := range []struct {
		list     string
		allowAny bool
		url      string
		allowed  bool
	}{
		{"", false, srv.URL, false},                            // nothing listed
		{"", true, srv.URL, false},                             // loopback, even with allow-any
		{"localhost", false, "http://localhost" + port, false}, // the name matches, its loopback addresses are not listed
		{"localhost, 127.0.0.0/8, ::1", false, "http://localhost" + port, true},
		{"127.0.0.0/8, ::1", false, "http://localhost" + port, true}, // an unlisted name into a listed block
		{"10.0.0.0/8", false, "http://localhost" + port, false},      // an unlisted name outside the listed blocks
		{"127.0.0.1", false, srv.URL, true},
	} {
		cfg := DefaultAmfClientConfig()
		cfg.Destinations, _ = ParseDestinations(c.list, c.allowAny)
		client, err := NewAmfClientWithConfig(cfg)
		if err != nil {
			t.Fatal(err)
		}
		s.callbacked.Store(false)
		err = client.SendCallback(context.Background(), c.url, map[string]int{"a": 1})
		if c.allowed && err != nil {
			t.Errorf("%q allow-any %v, %s: %v", c.list, c.allowAny, c.url, err)
		}
		if !c.allowed && (!errors.Is(err, ErrDestinationNotAllowed) || s.callbacked.Load()) {
			t.Errorf("%q allow-any %v, %s: %v, reached %v; want ErrDestinationNotAllowed", c.list, c.allowAny, c.url, err, s.callbacked.Load())
		}
	}
}
