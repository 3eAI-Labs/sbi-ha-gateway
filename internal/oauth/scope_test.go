// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package oauth

import "testing"

func TestRequiredScope(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/nausf-auth/v1/ue-authentications", "nausf-auth"},
		{"/nudm-uecm/v1/imsi-001/registrations/amf-3gpp-access", "nudm-uecm"},
		{"/nudm-sdm/v1/imsi-001", "nudm-sdm"},
		{"/nsmf-pdusession/v1/sm-contexts/abc", "nsmf-pdusession"},
		{"/livez", ""},  // bypass
		{"/readyz", ""}, // bypass
		// The NRF's notifications: that shape alone.
		{"/nrf-notify/v1/0123456789abcdef0123456789abcdef/fedcba9876543210fedcba9876543210", ""},
		{"/nrf-notify/v1/0123456789abcdef0123456789abcdef/fedcba9876543210fedcba9876543210/x", "nrf-notify"},
		{"/nrf-notify/v1/../../nudm-sdm/v2/imsi-001/am-data", "nrf-notify"},
		{"/nrf-notify/v1/0123456789ABCDEF0123456789ABCDEF/fedcba9876543210fedcba9876543210", "nrf-notify"},
		// Pathological paths still fail-closed: the derived scope can't
		// possibly match an issued token, so the request is rejected.
		{"/", ""},
		{"/single", "single"},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			got := RequiredScope(c.path)
			if got != c.want {
				t.Fatalf("RequiredScope(%q) = %q, want %q", c.path, got, c.want)
			}
		})
	}
}

func TestHasScope(t *testing.T) {
	cases := []struct {
		token, required string
		want            bool
	}{
		{"", "", true}, // both empty = public
		{"nausf-auth nudm-sdm", "nausf-auth", true},     // present
		{"nudm-sdm nudm-uecm", "nausf-auth", false},     // absent
		{"  nausf-auth   nudm-sdm  ", "nudm-sdm", true}, // multi-space tolerant
		{"", "nausf-auth", false},                       // no scope, scope required
		{"nausf-auth", "", true},                        // public path doesn't care
		{"prefix-nausf-auth", "nausf-auth", false},      // exact-token match, not substring
	}
	for _, c := range cases {
		t.Run(c.token+"_"+c.required, func(t *testing.T) {
			if got := HasScope(c.token, c.required); got != c.want {
				t.Fatalf("HasScope(%q, %q) = %v, want %v", c.token, c.required, got, c.want)
			}
		})
	}
}
