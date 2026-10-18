// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

// Package oauth implements OAuth2 NF token authentication for 5G SBI per
// 3GPP TS 33.501 §13.4.1 (Client Credentials grant) and TS 29.510 §6.3
// (Nnrf_AccessToken). The validator is a chi-friendly resource-server
// component: it does not issue tokens, only verifies tokens issued by the NRF.
package oauth

import "errors"

// FailReason classifies a validation failure for telemetry and ProblemDetails
// mapping. Keep these stable — they show up as a Prometheus label value
// (oauth_validations_total{reason}) and as the `cause` field in 3GPP
// ProblemDetails responses (TS 29.500 §6.7.5), so renaming breaks dashboards
// and downstream NF expectations.
type FailReason string

const (
	ReasonOK              FailReason = "ok"
	ReasonMissingToken    FailReason = "missing_token"
	ReasonMalformed       FailReason = "malformed"
	ReasonUnknownKid      FailReason = "unknown_kid"
	ReasonInvalidSig      FailReason = "invalid_signature"
	ReasonExpired         FailReason = "expired"
	ReasonNotYetValid     FailReason = "not_yet_valid"
	ReasonWrongAudience   FailReason = "wrong_audience"
	ReasonMissingClaim    FailReason = "missing_claim"
	ReasonInsufficientSco FailReason = "insufficient_scope"
	ReasonDisallowedAlg   FailReason = "disallowed_alg"

	// RFC 8705 cert-bound access token failures. Three distinct reasons so
	// dashboards can distinguish "operator hasn't issued bound tokens yet"
	// (cnf_missing) from "attacker is replaying a stolen token over a new
	// TLS session" (cnf_mismatch).
	ReasonCnfMissing  FailReason = "cnf_missing"  // OAUTH_REQUIRE_CERT_BINDING=true and token has no cnf
	ReasonCnfNoCert   FailReason = "cnf_no_cert"  // token carries cnf but request had no peer cert
	ReasonCnfMismatch FailReason = "cnf_mismatch" // peer cert thumbprint != cnf.x5t#S256
)

// ValidationError carries a typed reason so the middleware can pick the right
// HTTP status, ProblemDetails cause, and metric label without string parsing
// the underlying jwx error chain.
type ValidationError struct {
	Reason FailReason
	Err    error
}

func (e *ValidationError) Error() string {
	if e.Err == nil {
		return string(e.Reason)
	}
	return string(e.Reason) + ": " + e.Err.Error()
}

func (e *ValidationError) Unwrap() error { return e.Err }

func newErr(reason FailReason, err error) *ValidationError {
	return &ValidationError{Reason: reason, Err: err}
}

// AsValidationError extracts the typed reason from any error returned by this
// package. Callers in the middleware path use it to map → HTTP/ProblemDetails.
func AsValidationError(err error) (*ValidationError, bool) {
	var ve *ValidationError
	if errors.As(err, &ve) {
		return ve, true
	}
	return nil, false
}
