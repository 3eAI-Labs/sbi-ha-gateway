// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nats

import "testing"

func TestJetStreamPublishReply(t *testing.T) {
	cases := []struct {
		name   string
		data   string
		stream string
		ok     bool
	}{
		// What nats-server 2.10 writes: hand-built, with a space after the comma.
		{"acknowledgement", `{"stream":"CORE_EVENTS", "seq":7}`, "CORE_EVENTS", true},
		{"acknowledgement with domain", `{"stream":"S", "domain":"hub", "seq":1}`, "S", true},
		{"duplicate", `{"stream":"S","seq":1,"duplicate":true}`, "S", true},
		{"publish error", `{"error":{"code":400,"err_code":10109,"description":"invalid operation on sealed stream"},"stream":"S","seq":0}`, "S", true},

		{"application reply with a stream member", `{"stream":"S","seq":1,"supi":"imsi-001010000000001"}`, "", false},
		{"application reply", `{"authVector":{"rand":"r"},"supi":"imsi-001010000000001"}`, "", false},
		{"stream not a string", `{"stream":1,"seq":1}`, "", false},
		{"empty stream", `{"stream":"","seq":1}`, "", false},
		{"not an object", `["stream"]`, "", false},
		{"not JSON", `"stream" pong`, "", false},
		{"empty", ``, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stream, ok := jetStreamPublishReply([]byte(c.data))
			if ok != c.ok || stream != c.stream {
				t.Fatalf("jetStreamPublishReply(%s) = %q, %v; want %q, %v", c.data, stream, ok, c.stream, c.ok)
			}
		})
	}
}
