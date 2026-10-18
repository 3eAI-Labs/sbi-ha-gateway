// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nats_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/nats"
	natsserver "github.com/nats-io/nats-server/v2/server"
	gnats "github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
)

func runServer(opts *natsserver.Options) *natsserver.Server {
	if opts == nil {
		opts = &natsserver.Options{
			Port: -1,
		}
	}
	s, err := natsserver.NewServer(opts)
	if err != nil {
		panic(err)
	}
	go s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		panic("not ready for connections")
	}
	return s
}

func TestNatsClient_Integration(t *testing.T) {
	s := runServer(nil)
	defer s.Shutdown()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	client, err := nats.NewClient(s.ClientURL(), logger)
	assert.NoError(t, err)
	defer client.Close()

	assert.True(t, client.IsConnected())
	assert.NotNil(t, client.GetConn())

	// Test Request
	ctx := context.Background()
	subject := "test.request"

	// Subscriber for the request
	_, err = client.GetConn().Subscribe(subject, func(m *gnats.Msg) {
		_ = m.Respond([]byte("pong"))
	})
	assert.NoError(t, err)

	resp, err := client.Request(ctx, subject, []byte("ping"), 1*time.Second)
	assert.NoError(t, err)
	assert.Equal(t, "pong", string(resp))

	// Test Publish
	err = client.Publish("test.publish", []byte("hello"))
	assert.NoError(t, err)
}

func TestPublisher_PublishEvent(t *testing.T) {
	s := runServer(nil)
	defer s.Shutdown()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	client, _ := nats.NewClient(s.ClientURL(), logger)
	defer client.Close()

	pub := nats.NewPublisher(client.GetConn(), logger)

	subCh := make(chan []byte, 1)
	_, err := client.GetConn().Subscribe("events.test", func(m *gnats.Msg) {
		subCh <- m.Data
	})
	assert.NoError(t, err)

	event := map[string]string{"foo": "bar"}
	err = pub.PublishEvent("events.test", event)
	assert.NoError(t, err)

	select {
	case data := <-subCh:
		var received map[string]string
		assert.NoError(t, json.Unmarshal(data, &received))
		assert.Equal(t, "bar", received["foo"])
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for event")
	}
}

func TestPublisher_PublishEvent_Error(t *testing.T) {
	pub := nats.NewPublisher(nil, slog.Default())
	// Use a channel to trigger marshal error
	err := pub.PublishEvent("test", make(chan int))
	assert.Error(t, err)
}

func TestSubscriber_Start(t *testing.T) {
	s := runServer(nil)
	defer s.Shutdown()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	client, _ := nats.NewClient(s.ClientURL(), logger)
	defer client.Close()

	sub := nats.NewSubscriber(client.GetConn(), logger)
	err := sub.Start()
	assert.NoError(t, err)

	// Trigger the subscription callback
	assert.NoError(t, client.Publish("5g.data.notify", []byte(`{"callbackUri": "http://localhost", "changeItem": {}}`)))
	time.Sleep(100 * time.Millisecond)
}

func TestSubscriber_RetryLogic(t *testing.T) {

	s := runServer(nil)

	defer s.Shutdown()

	// Mock server that returns 500 to trigger retry

	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.WriteHeader(http.StatusInternalServerError)

	}))

	defer failServer.Close()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	client, _ := nats.NewClient(s.ClientURL(), logger)

	defer client.Close()

	sub := nats.NewSubscriber(client.GetConn(), logger)

	err := sub.Start()

	assert.NoError(t, err)

	// Trigger notification with failing URI

	payload := fmt.Sprintf(`{"callbackUri": "%s", "changeItem": {}}`, failServer.URL)

	assert.NoError(t, client.Publish("5g.data.notify", []byte(payload)))

	// Wait enough for at least one retry (1s backoff)

	time.Sleep(1200 * time.Millisecond)

}

func TestNatsClient_Request_Error(t *testing.T) {

	s := runServer(nil)

	defer s.Shutdown()

	client, _ := nats.NewClient(s.ClientURL(), slog.Default())

	// Request on subject with no subscribers should timeout

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)

	defer cancel()

	_, err := client.Request(ctx, "no.one.listening", []byte("ping"), 100*time.Millisecond)

	assert.Error(t, err)

}
