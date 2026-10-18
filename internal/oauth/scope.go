// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package oauth

import "strings"

// publicPaths bypasses scope enforcement entirely. Keep this list minimal —
// every entry is an explicit decision to skip OAuth2 authZ. The SBI port
// generally has no public surface (admin port hosts /metrics and friends), but
// future per-NF probes may need to land here.
var publicPaths = map[string]struct{}{
	"/livez":  {},
	"/readyz": {},
}

// RequiredScope returns the OAuth2 scope name a caller's token MUST contain to
// reach urlPath. It is derived from the URL prefix per 3GPP TS 29.501 §4.4.1
// — the service-name segment of the API root maps 1:1 to the OAuth2 scope
// string the NRF issues (TS 29.510 §6.3.5.2.4).
//
//	/nausf-auth/v1/...    → "nausf-auth"
//	/nudm-uecm/v1/...     → "nudm-uecm"
//	/nudm-sdm/v1/...      → "nudm-sdm"
//	/nsmf-pdusession/...  → "nsmf-pdusession"
//
// This auto-derive is deliberate: a static map drifts from routes and adding a
// handler without updating the map silently disables authZ for that handler.
// Auto-derive is fail-closed — if the path has no service prefix, scope is the
// path itself which will never match an issued token, so the request is
// rejected.
func RequiredScope(urlPath string) string {
	if _, public := publicPaths[urlPath]; public {
		return ""
	}
	trimmed := strings.TrimPrefix(urlPath, "/")
	if i := strings.IndexByte(trimmed, '/'); i > 0 {
		return trimmed[:i]
	}
	return trimmed
}

// HasScope reports whether tokenScope (the space-separated `scope` claim per
// RFC 6749 §3.3) contains the required scope. Empty required means public.
func HasScope(tokenScope, required string) bool {
	if required == "" {
		return true
	}
	if tokenScope == "" {
		return false
	}
	for _, s := range strings.Fields(tokenScope) {
		if s == required {
			return true
		}
	}
	return false
}
