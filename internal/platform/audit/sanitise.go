// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package audit

import (
	"encoding/json"
	"strings"
)

// sensitiveKeys is the case-folded set of JSON field names we ALWAYS strip
// before audit emission. List sources:
//   - 3GPP TS 33.501 §6.1 (auth vector fields: RAND, AUTN, KAusf, KAmf, KSeaf, CK, IK, XRES*)
//   - RFC 6749 / OAuth (authorization, access_token, refresh_token)
//   - RFC 6265 (cookie / set-cookie)
//
// The list is intentionally strict — false-positive redaction (over-masking
// a benign field that happens to match) is preferable to false-negative
// (auth vector reaching audit). Adding a new sensitive field is a one-line
// change; whitelisting an unintentionally-matched benign field requires a
// data-classification review and goes through a separate ADR.
var sensitiveKeys = map[string]struct{}{
	"authvector":    {},
	"authvectors":   {},
	"kausf":         {},
	"kamf":          {},
	"kseaf":         {},
	"ck":            {},
	"ik":            {},
	"rand":          {},
	"autn":          {},
	"auts":          {},
	"xresstar":      {},
	"xres":          {},
	"resstar":       {},
	"res":           {},
	"hresstar":      {},
	"hxresstar":     {},
	"authorization": {},
	"access_token":  {},
	"refresh_token": {},
	"id_token":      {},
	"cookie":        {},
	"set-cookie":    {},
	"setcookie":     {},
	"client_secret": {},
	"clientsecret":  {},
	"password":      {},
	"sk":            {},
	"sucipriv":      {},
	"privatekey":    {},
}

const redactedMarker = "[REDACTED]"

// SanitisePayload returns an audit-safe deep copy of payload with every
// sensitive key replaced by [REDACTED]. The original is never mutated.
//
// Implementation goes through JSON round-trip rather than reflection:
//  1. The shape we ultimately emit IS JSON (audit consumers parse it).
//  2. JSON serialisation already normalises struct tags, embedded fields,
//     and json.Marshaler implementations — anything weird the caller did
//     at the Go type level disappears here.
//  3. A reflection-based walker would have to re-implement all of those,
//     and the failure mode of getting it wrong is "secret slips through".
//
// Inputs that don't marshal to JSON (channels, functions) come back as the
// string "[unmarshalable]" — never as the original value. This matters
// because a caller passing a struct with a chan field would otherwise get
// a partial sanitisation.
func SanitisePayload(payload interface{}) interface{} {
	if payload == nil {
		return nil
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "[unmarshalable]"
	}
	var generic interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		return "[unmarshalable]"
	}
	return walkAndRedact(generic)
}

// walkAndRedact descends through map[string]interface{} / []interface{}
// trees produced by a JSON unmarshal into interface{}. Anything else is
// returned as-is — leaves carry no key, so no redaction decision applies.
func walkAndRedact(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, val := range t {
			if _, isSensitive := sensitiveKeys[strings.ToLower(k)]; isSensitive {
				out[k] = redactedMarker
				continue
			}
			out[k] = walkAndRedact(val)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, val := range t {
			out[i] = walkAndRedact(val)
		}
		return out
	default:
		return v
	}
}
