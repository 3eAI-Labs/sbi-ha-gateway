// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

// Package audit is this gateway's adapter layer over internal/platform/audit.
//
// Two responsibilities:
//
//  1. Resolve the OAuth-authenticated NF identity (sub claim) into the
//     userID field of the audit event. Falls back to "anonymous" when the
//     request arrived without OAuth (dev mode / OAUTH_DISABLED=true).
//
//  2. Apply the carrier-grade redaction primitives from internal/platform/audit
//     (MaskSUPI, SanitisePayload) before the event leaves this process.
//     Handlers must NOT call internal/platform/audit.Log directly — that bypasses
//     the redaction and would put subscriber identities and key material
//     into the audit trail.
package audit

import (
	"context"
	"net/http"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/authctx"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
	cgaudit "github.com/3eAI-Labs/sbi-ha-gateway/internal/platform/audit"
)

// Log emits an audit event for a state-changing SBI operation.
//
//	r        — the inbound HTTP request; used to extract the OAuth sub claim
//	action   — the operation, by its OpenAPI operationId: "3GppRegistration", "ConfirmAuth"
//	resource — service short name, e.g. "nudm-uecm" / "nausf-auth"
//	supi     — raw SUPI (will be MaskSUPI'd before emission); empty for ops
//	           without an obvious subject identifier
//	payload  — what the event may carry besides (will be SanitisePayload'd); the SBI
//	           handler passes nil: it does not interpret bodies, so it cannot vouch for one
//
// Emit is non-blocking: when the publisher queue is full the event is
// dropped and the audit_events_total{result="dropped"} metric increments.
// Audit must never become a back-pressure source for the request path.
func Log(r *http.Request, action, resource, supi string, payload interface{}) {
	userID := userFromRequest(r)
	maskedID := cgaudit.MaskSUPI(supi)
	safePayload := cgaudit.SanitisePayload(payload)

	pre := cgaudit.Drops()
	cgaudit.Log(r.Context(), userID, action, resource, maskedID, safePayload)
	post := cgaudit.Drops()
	if post > pre {
		metrics.RecordAuditEvent("dropped")
		return
	}
	metrics.RecordAuditEvent("emitted")
}

// userFromRequest pulls the OAuth `sub` claim (consumer NF instance ID)
// from the request context. When OAuth is disabled or no token was
// presented, returns "anonymous" so the field is never empty —
// downstream audit consumers correlate on user_id.
func userFromRequest(r *http.Request) string {
	if r == nil {
		return "anonymous"
	}
	if sub := authctx.NFSubjectFromContext(r.Context()); sub != "" {
		return sub
	}
	return "anonymous"
}

// LogCtx is a context-only variant for code paths without an *http.Request
// (NATS callbacks etc.). userID must be supplied explicitly because no
// OAuth context is implied off the SBI listener.
func LogCtx(ctx context.Context, userID, action, resource, supi string, payload interface{}) {
	if userID == "" {
		userID = "anonymous"
	}
	maskedID := cgaudit.MaskSUPI(supi)
	safePayload := cgaudit.SanitisePayload(payload)

	pre := cgaudit.Drops()
	cgaudit.Log(ctx, userID, action, resource, maskedID, safePayload)
	post := cgaudit.Drops()
	if post > pre {
		metrics.RecordAuditEvent("dropped")
		return
	}
	metrics.RecordAuditEvent("emitted")
}
