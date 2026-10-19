// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/models"
	"github.com/go-chi/chi/v5/middleware"
)

// Recover answers a handler's panic with 500 SYSTEM_FAILURE as ProblemDetails (TS 29.500
// Table 5.2.7.2-1) and logs it, with its stack, as one line of the gateway's log. When the
// response has already begun, nothing correct can follow it: the stream is aborted
// (http.ErrAbortHandler), so the network function sees a reset, not a truncated answer.
// http.ErrAbortHandler itself is passed on unlogged.
func Recover(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			defer func() {
				rvr := recover()
				if rvr == nil {
					return
				}
				if rvr == http.ErrAbortHandler { //nolint:errorlint // recover() returns the value itself
					panic(rvr)
				}
				log.LogAttrs(r.Context(), slog.LevelError, "Handler panicked",
					slog.Any("panic", rvr),
					slog.String("route", getRoutePattern(r)),
					slog.String("request_id", middleware.GetReqID(r.Context())),
					slog.String("stack", string(debug.Stack())),
				)
				if ww.Status() != 0 {
					panic(http.ErrAbortHandler)
				}
				ww.Header().Set("Content-Type", "application/problem+json")
				ww.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(ww).Encode(models.ProblemDetails{
					Title:  http.StatusText(http.StatusInternalServerError),
					Status: http.StatusInternalServerError,
					Cause:  "SYSTEM_FAILURE",
					Detail: "Internal error",
				})
			}()
			next.ServeHTTP(ww, r)
		})
	}
}
