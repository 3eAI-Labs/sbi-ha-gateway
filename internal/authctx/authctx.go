// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

// Package authctx is a leaf package that carries the OAuth-authenticated NF
// identity through request context. Lives outside internal/server so leaf
// packages (internal/audit, internal/handlers) can read the identity
// without pulling in the server package — which would create an import
// cycle, since internal/server imports internal/handlers for routes.
package authctx

import "context"

// ctxKey is unexported so other packages can't accidentally collide with
// our context keys via untyped string literals.
type ctxKey int

const ctxKeyNFSubject ctxKey = iota

// WithNFSubject returns a child context carrying sub as the authenticated
// NF instance ID. Called from the OAuth middleware after the validator
// returned successful Claims.
func WithNFSubject(parent context.Context, sub string) context.Context {
	return context.WithValue(parent, ctxKeyNFSubject, sub)
}

// NFSubjectFromContext returns the OAuth `sub` claim (consumer NF instance
// ID) of the authenticated caller, if any. Returns "" when OAuth is
// disabled or the path was on the public allowlist.
func NFSubjectFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyNFSubject).(string); ok {
		return v
	}
	return ""
}
