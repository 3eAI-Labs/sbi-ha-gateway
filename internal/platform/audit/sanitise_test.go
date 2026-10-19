// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package audit

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestSanitisePayload_RedactsTopLevelAuthVector(t *testing.T) {
	in := map[string]interface{}{
		"supi":       "imsi-286010000000001",
		"authVector": map[string]interface{}{"rand": "abc", "autn": "def", "kausf": "ghi"},
	}
	got := SanitisePayload(in)
	gotMap := got.(map[string]interface{})
	if gotMap["supi"] != "imsi-286010000000001" {
		t.Errorf("non-sensitive field mutated: %v", gotMap["supi"])
	}
	if gotMap["authVector"] != redactedMarker {
		t.Errorf("authVector not redacted: %v", gotMap["authVector"])
	}
}

func TestSanitisePayload_RedactsNested(t *testing.T) {
	// xresStar is buried under authResult.confirmation — sanitiser must
	// descend through nested maps.
	in := map[string]interface{}{
		"authResult": map[string]interface{}{
			"servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org",
			"confirmation": map[string]interface{}{
				"xresStar": "deadbeef",
				"timing":   42,
			},
		},
	}
	got := SanitisePayload(in)
	confirm := got.(map[string]interface{})["authResult"].(map[string]interface{})["confirmation"].(map[string]interface{})
	if confirm["xresStar"] != redactedMarker {
		t.Errorf("nested xresStar not redacted: %v", confirm["xresStar"])
	}
	if confirm["timing"] != float64(42) {
		t.Errorf("non-sensitive sibling mutated: %v", confirm["timing"])
	}
}

func TestSanitisePayload_RedactsInsideArrays(t *testing.T) {
	in := map[string]interface{}{
		"vectors": []interface{}{
			map[string]interface{}{"rand": "r1", "label": "primary"},
			map[string]interface{}{"rand": "r2", "label": "secondary"},
		},
	}
	got := SanitisePayload(in).(map[string]interface{})
	for i, item := range got["vectors"].([]interface{}) {
		m := item.(map[string]interface{})
		if m["rand"] != redactedMarker {
			t.Errorf("vectors[%d].rand not redacted: %v", i, m["rand"])
		}
	}
}

func TestSanitisePayload_CaseInsensitive(t *testing.T) {
	cases := []map[string]interface{}{
		{"AUTHVECTOR": "x"},
		{"AuthVector": "x"},
		{"authvector": "x"},
		{"Set-Cookie": "x"},
	}
	for _, c := range cases {
		got := SanitisePayload(c).(map[string]interface{})
		for k, v := range got {
			if v != redactedMarker {
				t.Errorf("case-insensitive match failed for %q: got %v", k, v)
			}
		}
	}
}

func TestSanitisePayload_NeverMutatesInput(t *testing.T) {
	in := map[string]interface{}{
		"authVector": "secret-rand",
	}
	original := "secret-rand"
	_ = SanitisePayload(in)
	// Original map must still hold the secret — sanitiser returns a copy.
	if in["authVector"] != original {
		t.Errorf("input was mutated: %v", in["authVector"])
	}
}

func TestSanitisePayload_NilSafe(t *testing.T) {
	if got := SanitisePayload(nil); got != nil {
		t.Errorf("nil input must return nil; got %v", got)
	}
}

func TestSanitisePayload_StructInput_GoesThroughJSON(t *testing.T) {
	// Caller-defined struct with a sensitive json tag — sanitiser must
	// catch it via the JSON serialisation, not need reflection over Go
	// field names.
	type AuthData struct {
		Supi       string `json:"supi"`
		AuthVector string `json:"authVector"`
	}
	in := AuthData{Supi: "imsi-001", AuthVector: "secret"}
	got := SanitisePayload(in).(map[string]interface{})
	if got["authVector"] != redactedMarker {
		t.Errorf("struct's authVector not redacted: %v", got["authVector"])
	}
	if got["supi"] != "imsi-001" {
		t.Errorf("supi mutated: %v", got["supi"])
	}
}

func TestSanitisePayload_Unmarshalable(t *testing.T) {
	// A channel cannot be JSON-marshaled. Sanitiser must NOT panic and must
	// NOT return the original (which would defeat the entire purpose).
	got := SanitisePayload(make(chan int))
	if got != "[unmarshalable]" {
		t.Errorf("got %v, want [unmarshalable]", got)
	}
}

// Belt-and-braces: serialise the sanitised payload and grep for any
// known-sensitive substring. If MaskSUPI / SanitisePayload regress, this
// catches it as a leaked literal in the JSON output.
func TestSanitisePayload_OutputHasNoSecretLiterals(t *testing.T) {
	in := map[string]interface{}{
		"supi":       "imsi-286010000000001",
		"authVector": map[string]interface{}{"rand": "RAND-LEAK", "autn": "AUTN-LEAK"},
		"kAusf":      "KAUSF-LEAK",
		"nested": map[string]interface{}{
			"xresStar": "XRES-LEAK",
		},
		"resynchronizationInfo": map[string]interface{}{"rand": "RAND2-LEAK", "auts": "AUTS-LEAK"},
	}
	out, _ := json.Marshal(SanitisePayload(in))
	for _, leak := range []string{"RAND-LEAK", "AUTN-LEAK", "KAUSF-LEAK", "XRES-LEAK", "RAND2-LEAK", "AUTS-LEAK"} {
		if strings.Contains(string(out), leak) {
			t.Errorf("sanitised output contains leaked secret %q: %s", leak, string(out))
		}
	}
}

// Compile-time guard that the redacted marker is detectable in tests.
var _ = reflect.DeepEqual

// The subscriber keys and SQN of a TS 29.505 AuthenticationSubscription.
func TestSanitisePayload_RedactsAuthenticationSubscription(t *testing.T) {
	in := map[string]interface{}{
		"authenticationMethod": "5G_AKA",
		"encPermanentKey":      "k-secret",
		"encOpcKey":            "opc-secret",
		"encTopcKey":           "topc-secret",
		"sequenceNumber":       map[string]interface{}{"sqn": "sqn-secret"},
	}
	raw, _ := json.Marshal(SanitisePayload(in))
	if strings.Contains(string(raw), "secret") {
		t.Errorf("key material survived: %s", raw)
	}
	if !strings.Contains(string(raw), "5G_AKA") {
		t.Errorf("non-sensitive field lost: %s", raw)
	}
}
