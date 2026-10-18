// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A real server refuses a body with 204 (http.ErrBodyNotAllowed); writing "null" there
// counted every successful PATCH and DELETE as an encoding failure.
func TestWriteJSON_NoContentWritesNoBody(t *testing.T) {
	h := &handlers.BaseHandler{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		h.WriteJSON(w, http.StatusNoContent, nil)
	}))
	defer srv.Close()

	failures := func() float64 {
		var m dto.Metric
		require.NoError(t, metrics.ErrorsTotal.WithLabelValues("encode", "json_response_failed").Write(&m))
		return m.GetCounter().GetValue()
	}
	before := failures()
	resp, err := http.Get(srv.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	assert.Equal(t, before, failures(), "encoding failures counted for a 204")
}
