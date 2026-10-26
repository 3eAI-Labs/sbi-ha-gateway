// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
)

// The NRF's notifications reach their callback without an access token, through the rest of
// the chain; nothing else does.
func TestNewRouter_NRFNotificationsWithoutToken(t *testing.T) {
	v, _, _ := mintTestValidator(t, "udm.local")
	r := NewRouter(RouterConfig{
		OAuthValidator: v,
		NRFNotifications: func(r chi.Router) {
			r.Post("/nrf-notify/v1/{replica}/{key}", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})
		},
	})
	hex := strings.Repeat("0a", 16)
	for path, want := range map[string]int{
		"/nrf-notify/v1/" + hex + "/" + hex:         http.StatusNoContent,
		"/nrf-notify/v1/" + hex + "/not-a-key":      http.StatusUnauthorized,
		"/nudm-sdm/v2/imsi-001010000000001/am-data": http.StatusUnauthorized,
	} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}")))
		assert.Equal(t, want, rec.Code, path)
	}
}
