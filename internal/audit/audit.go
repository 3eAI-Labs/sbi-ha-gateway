// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

// Package audit is this gateway's adapter layer over internal/platform/audit.
//
// Two responsibilities:
//
//  1. Resolve who acted into the userID field of the audit event: the OAuth-authenticated
//     NF identity (sub claim), the client certificate's NF instance ID for a request OAuth
//     refused, "nats" for what an application asked for over NATS, "anonymous" otherwise.
//
//  2. Apply the carrier-grade redaction primitives from internal/platform/audit before the
//     event leaves this process: subscriber identities are masked (MaskSUPI), and no body
//     travels — the gateway does not interpret bodies, so it cannot tell key material from
//     the rest. Handlers must NOT call internal/platform/audit directly.
package audit

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/authctx"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
	cgaudit "github.com/3eAI-Labs/sbi-ha-gateway/internal/platform/audit"
	"github.com/go-chi/chi/v5/middleware"
)

// Outcomes of an audited request or action.
const (
	Success  = "success"
	Rejected = "rejected" // refused: a 4xx, OAuth, a destination not allowed
	Failed   = "failed"   // could not be carried out: a 5xx, a network function that did not answer
)

// natsUser is who acted for the actions an application asked for over NATS: the gateway
// knows the subject, not the publisher.
const natsUser = "nats"

// Request audits a state-changing SBI operation and how it ended. action is its OpenAPI
// operationId, resource the API name, supi the subscriber (masked here), status the HTTP status
// the network function got, cause the ProblemDetails cause of an error.
//
// Emit is non-blocking: when the publisher queue is full the event is dropped and the
// audit_events_total{result="dropped"} metric increments. Audit must never become a
// back-pressure source for the request path.
func Request(r *http.Request, action, resource, supi string, status int, cause string) {
	emit(r.Context(), cgaudit.Event{
		UserID:     userFromRequest(r),
		Action:     action,
		Resource:   resource,
		ResourceID: cgaudit.MaskSUPI(supi),
		Outcome:    outcomeOf(status),
		Status:     status,
		Cause:      cause,
		RequestID:  middleware.GetReqID(r.Context()),
	})
}

// Refused audits a request OAuth turned away before any operation: userID is the client
// certificate's NF instance ID, if any; resource the API name; cause the rejection reason.
func Refused(r *http.Request, userID, resource string, status int, cause string) {
	if userID == "" {
		userID = "anonymous"
	}
	emit(r.Context(), cgaudit.Event{
		UserID:    userID,
		Action:    "AccessToken",
		Resource:  resource,
		Outcome:   Rejected,
		Status:    status,
		Cause:     cause,
		RequestID: middleware.GetReqID(r.Context()),
	})
}

// Action audits what the gateway did for an application over NATS — a notification
// delivered, an SMS sent: target is the network function addressed (scheme://host:port),
// supi the subscriber when known (masked here).
func Action(ctx context.Context, action, resource, supi, target, outcome, cause string) {
	emit(ctx, cgaudit.Event{
		UserID:     natsUser,
		Action:     action,
		Resource:   resource,
		ResourceID: cgaudit.MaskSUPI(supi),
		Outcome:    outcome,
		Cause:      cause,
		Target:     target,
	})
}

func emit(ctx context.Context, ev cgaudit.Event) {
	pre := cgaudit.Drops()
	cgaudit.Emit(ctx, ev)
	if cgaudit.Drops() > pre {
		metrics.RecordAuditEvent("dropped")
		return
	}
	metrics.RecordAuditEvent("emitted")
}

func outcomeOf(status int) string {
	switch {
	case status >= 200 && status < 300:
		return Success
	case status >= 400 && status < 500:
		return Rejected
	default:
		return Failed // 5xx, or nothing answered
	}
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

// maxCauseBody bounds what Recorder keeps of an error body to find its cause.
const maxCauseBody = 2048

// Recorder is the ResponseWriter of an audited request: it keeps the status and, of an error
// response, enough of the body to read its ProblemDetails cause. A success body is not kept.
type Recorder struct {
	http.ResponseWriter
	status int
	body   []byte
}

// NewRecorder wraps w.
func NewRecorder(w http.ResponseWriter) *Recorder { return &Recorder{ResponseWriter: w} }

func (rec *Recorder) WriteHeader(code int) {
	if rec.status == 0 {
		rec.status = code
	}
	rec.ResponseWriter.WriteHeader(code)
}

func (rec *Recorder) Write(b []byte) (int, error) {
	if rec.status == 0 {
		rec.status = http.StatusOK
	}
	if rec.status >= 400 && len(rec.body) < maxCauseBody {
		rec.body = append(rec.body, b[:min(len(b), maxCauseBody-len(rec.body))]...)
	}
	return rec.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (rec *Recorder) Unwrap() http.ResponseWriter { return rec.ResponseWriter }

// Status is the status written; 0 when nothing was.
func (rec *Recorder) Status() int { return rec.status }

// Cause is the ProblemDetails cause of an error response; empty otherwise.
func (rec *Recorder) Cause() string {
	var pd struct {
		Cause string `json:"cause"`
	}
	if json.Unmarshal(rec.body, &pd) != nil {
		return ""
	}
	return pd.Cause
}
