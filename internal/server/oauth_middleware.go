// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/authctx"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/models"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/oauth"
)

// NFSubjectFromContext is a thin re-export of authctx.NFSubjectFromContext,
// kept for backwards compat with internal callers (rate limiter test) that
// imported it from this package before the authctx leaf-package split.
// New code should import internal/authctx directly.
func NFSubjectFromContext(ctx context.Context) string {
	return authctx.NFSubjectFromContext(ctx)
}

// OAuthMiddleware enforces OAuth2 NF token authentication per TS 33.501
// §13.4.1. When validator is nil the middleware is a passthrough — used in
// development with OAUTH_DISABLED=true. Public paths (livez/readyz) bypass
// the bearer check but still get the empty-string sub injected, so the rate
// limiter handles them via its IP fallback.
func OAuthMiddleware(validator oauth.Validator) func(http.Handler) http.Handler {
	if validator == nil {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			required := oauth.RequiredScope(r.URL.Path)
			if required == "" {
				// Public path — skip token check entirely. Anything in
				// publicPaths is an explicit operator decision (see
				// oauth/scope.go).
				next.ServeHTTP(w, r)
				return
			}

			bearer, ok := extractBearer(r.Header.Get("Authorization"))
			if !ok {
				writeOAuthFail(w, http.StatusUnauthorized,
					"missing_bearer", oauth.ReasonMissingToken,
					"Authorization header missing or not Bearer-typed")
				return
			}

			// PeerIdentityMiddleware (when present in the chain) injected
			// the peer cert; in plaintext / non-mTLS deployments this is
			// nil and the validator handles the unbound-token path.
			var peerThumbprint []byte
			if peer := PeerIdentityFromContext(r.Context()); peer != nil {
				peerThumbprint = peer.CertThumbprint()
			}

			claims, err := validator.Validate(r.Context(), bearer, peerThumbprint)
			if err != nil {
				ve, _ := oauth.AsValidationError(err)
				reason := oauth.ReasonMalformed
				if ve != nil {
					reason = ve.Reason
				}
				status, cause, detail := mapReason(reason)
				writeOAuthFail(w, status, cause, reason, detail)
				return
			}

			if !oauth.HasScope(claims.Scope, required) {
				writeOAuthFail(w, http.StatusForbidden,
					"INSUFFICIENT_SCOPES", oauth.ReasonInsufficientSco,
					"token scope does not include "+required)
				return
			}

			metrics.RecordOAuthValidation("ok", string(oauth.ReasonOK))

			ctx := authctx.WithNFSubject(r.Context(), claims.Subject)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractBearer parses the Authorization header per RFC 6750 §2.1. Returns
// (token, true) on success. Anything other than `Bearer <token>` is rejected
// — including `bearer` with lowercase b would technically be permitted by
// RFC but rejected here because every spec-conformant 5G NF emits "Bearer".
func extractBearer(authz string) (string, bool) {
	const prefix = "Bearer "
	if len(authz) <= len(prefix) || !strings.HasPrefix(authz, prefix) {
		return "", false
	}
	tok := strings.TrimSpace(authz[len(prefix):])
	if tok == "" {
		return "", false
	}
	return tok, true
}

// mapReason translates a validator FailReason into the HTTP status, 3GPP
// cause string, and a short detail. The cause strings come from TS 29.500
// §6.7.5 Table 6.7.5-1 — these are the values 5G NFs expect to see in
// ProblemDetails.cause when triggering retry/refresh logic.
func mapReason(r oauth.FailReason) (status int, cause string, detail string) {
	switch r {
	case oauth.ReasonExpired:
		return http.StatusUnauthorized, "TOKEN_EXPIRED", "access token has expired"
	case oauth.ReasonNotYetValid:
		return http.StatusUnauthorized, "INVALID_TOKEN", "access token not yet valid"
	case oauth.ReasonWrongAudience:
		return http.StatusForbidden, "INVALID_TOKEN", "audience mismatch"
	case oauth.ReasonInsufficientSco:
		return http.StatusForbidden, "INSUFFICIENT_SCOPES", "scope insufficient"
	case oauth.ReasonMissingClaim:
		return http.StatusUnauthorized, "INVALID_TOKEN", "required claim missing"
	case oauth.ReasonUnknownKid:
		return http.StatusUnauthorized, "INVALID_TOKEN", "signing key not recognised"
	case oauth.ReasonInvalidSig:
		return http.StatusUnauthorized, "INVALID_TOKEN", "signature verification failed"
	case oauth.ReasonDisallowedAlg:
		return http.StatusUnauthorized, "INVALID_TOKEN", "token algorithm not permitted"
	case oauth.ReasonMissingToken:
		return http.StatusUnauthorized, "missing_bearer", "Authorization header missing"
	// RFC 8705 binding failures. We use the spec's "TOKEN_BINDING_FAILED"
	// cause string per TS 29.500 §6.7.5 so peer NFs branch on the same
	// label whether the token was unbound, presented over the wrong
	// connection, or simply replayed.
	case oauth.ReasonCnfMissing:
		return http.StatusUnauthorized, "TOKEN_BINDING_FAILED", "cert-bound token required (cnf claim missing)"
	case oauth.ReasonCnfNoCert:
		return http.StatusUnauthorized, "TOKEN_BINDING_FAILED", "token is cert-bound but no peer cert presented"
	case oauth.ReasonCnfMismatch:
		return http.StatusUnauthorized, "TOKEN_BINDING_FAILED", "peer cert does not match token binding"
	default:
		return http.StatusUnauthorized, "INVALID_TOKEN", "token validation failed"
	}
}

func writeOAuthFail(w http.ResponseWriter, status int, cause string, reason oauth.FailReason, detail string) {
	metrics.RecordOAuthValidation("fail", string(reason))

	// RFC 6750 §3 — challenge header on 401. 403 doesn't carry one.
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate",
			`Bearer error="invalid_token", error_description="`+detail+`"`)
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(models.ProblemDetails{
		Type:   "https://tools.ietf.org/html/rfc6750",
		Title:  http.StatusText(status),
		Status: status,
		Detail: detail,
		Cause:  cause,
	})
}
