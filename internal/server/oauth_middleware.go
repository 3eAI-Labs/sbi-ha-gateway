// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/audit"
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
				// No token: the challenge names no error (TS 29.500 clause 6.7.3).
				writeOAuthFail(w, r, http.StatusUnauthorized, "", "", oauth.ReasonMissingToken,
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
				// Expired, malformed, for another audience, bound to another certificate:
				// a token "deemed invalid" is 401 invalid_token (TS 29.500 clause 6.7.3).
				writeOAuthFail(w, r, http.StatusUnauthorized, "invalid_token", "", reason, reasonDetail(reason))
				return
			}

			if !oauth.HasScope(claims.Scope, required) {
				writeOAuthFail(w, r, http.StatusForbidden, "insufficient_scope", required,
					oauth.ReasonInsufficientSco, "token scope does not include the API's scope")
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

// reasonDetail is the ProblemDetails detail and the error_description of a validator
// FailReason. TS 29.500 defines no ProblemDetails cause for these rejections: the
// WWW-Authenticate challenge is what network functions act on, so none is sent.
func reasonDetail(r oauth.FailReason) string {
	switch r {
	case oauth.ReasonExpired:
		return "access token has expired"
	case oauth.ReasonNotYetValid:
		return "access token not yet valid"
	case oauth.ReasonWrongAudience:
		return "audience mismatch"
	case oauth.ReasonMissingClaim:
		return "required claim missing"
	case oauth.ReasonUnknownKid:
		return "signing key not recognised"
	case oauth.ReasonInvalidSig:
		return "signature verification failed"
	case oauth.ReasonDisallowedAlg:
		return "token algorithm not permitted"
	// RFC 8705 binding failures.
	case oauth.ReasonCnfMissing:
		return "cert-bound token required (cnf claim missing)"
	case oauth.ReasonCnfNoCert:
		return "token is cert-bound but no peer cert presented"
	case oauth.ReasonCnfMismatch:
		return "peer cert does not match token binding"
	default:
		return "token validation failed"
	}
}

// writeOAuthFail rejects r with status, the WWW-Authenticate challenge of TS 29.500 clause
// 6.7.3 and ProblemDetails. errCode is RFC 6750's error, empty when no token was sent; scope
// is the scope needed, with insufficient_scope.
func writeOAuthFail(w http.ResponseWriter, r *http.Request, status int, errCode, scope string, reason oauth.FailReason, detail string) {
	metrics.RecordOAuthValidation("fail", string(reason))
	var peer string
	if id := PeerIdentityFromContext(r.Context()); id != nil {
		peer = id.NFInstanceID
	}
	audit.Refused(r, peer, oauth.RequiredScope(r.URL.Path), status, string(reason))

	params := []string{"realm=" + quoted(apiURI(r))}
	if errCode != "" {
		params = append(params, `error="`+errCode+`"`, `error_description="`+rfc6750Chars(detail, true)+`"`)
	}
	if scope != "" {
		params = append(params, `scope="`+rfc6750Chars(scope, false)+`"`)
	}
	w.Header().Set("WWW-Authenticate", "Bearer "+strings.Join(params, ", "))
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(models.ProblemDetails{
		Type:   "https://tools.ietf.org/html/rfc6750",
		Title:  http.StatusText(status),
		Status: status,
		Detail: detail,
	})
}

// apiURI is the realm of TS 29.500 clause 6.7.3, the URI of the API the access failed for:
// {apiRoot}/{apiName}/{apiVersion} (TS 29.501 clause 4.4.1). The path is taken escaped, so
// it holds no quote.
func apiURI(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	segments := strings.SplitN(strings.TrimPrefix(r.URL.EscapedPath(), "/"), "/", 3)
	if len(segments) > 2 {
		segments = segments[:2]
	}
	return strings.TrimSuffix(scheme+"://"+r.Host+"/"+strings.Join(segments, "/"), "/")
}

// quoted is s as an RFC 9110 quoted-string.
func quoted(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// rfc6750Chars keeps the characters RFC 6750 clause 3 allows in error_description (space
// too) or in a scope-token: printable ASCII but '"' and '\', which may not be escaped there.
func rfc6750Chars(s string, space bool) string {
	return strings.Map(func(c rune) rune {
		if c == '"' || c == '\\' || c > '~' || c < ' ' || (c == ' ' && !space) {
			return -1
		}
		return c
	}, s)
}
