// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nrf

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient_APIRoot(t *testing.T) {
	for _, ok := range []string{"https://nrf.example", "https://nrf.example:8443/", "http://10.0.0.1/prefix"} {
		_, err := NewClient(ok, http.DefaultClient)
		assert.NoError(t, err, ok)
	}
	for _, bad := range []string{"", "nrf.example", "ftp://nrf.example", "https://", "https://nrf.example/?a=1",
		"https://nrf.example/#f", "https://u:p@nrf.example"} {
		_, err := NewClient(bad, http.DefaultClient)
		assert.Error(t, err, bad)
	}
}

// The NRF's redirection (TS 29.510 Table 6.1.3.3.3.3-3: 307/308 with Location) is followed
// with the method and the body.
func TestClient_FollowsRedirect(t *testing.T) {
	nrf := newFakeNRF(t)
	target := httptest.NewUnstartedServer(nrf)
	target.EnableHTTP2 = true
	target.StartTLS()
	t.Cleanup(target.Close)
	front := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL+r.URL.Path)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	front.EnableHTTP2 = true
	front.StartTLS()
	t.Cleanup(front.Close)
	c, err := NewClient(front.URL, target.Client()) // both serve httptest's certificate
	require.NoError(t, err)

	p := testProfile(t)
	hb, err := c.Register(context.Background(), p)
	require.NoError(t, err)
	assert.Equal(t, 10*time.Second, hb)
	assert.True(t, nrf.registered(p.InstanceID))
}

func TestClient_StatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"status":400,"cause":"MANDATORY_IE_MISSING"}`)
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL, srv.Client())
	require.NoError(t, err)
	_, err = c.Register(context.Background(), testProfile(t))
	var se *StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusBadRequest, se.Status)
	assert.Contains(t, err.Error(), "MANDATORY_IE_MISSING")
	assert.False(t, IsNotFound(err))

	_, err = c.Heartbeat(context.Background(), testProfile(t))
	assert.Contains(t, err.Error(), "nrf heartbeat: HTTP 400")
}

func TestClient_TransportError(t *testing.T) {
	c, err := NewClient("http://127.0.0.1:1", http.DefaultClient)
	require.NoError(t, err)
	_, err = c.Register(context.Background(), testProfile(t))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nrf register")
	var se *StatusError
	assert.NotErrorAs(t, err, &se, "no answer is not an NRF status")
}
