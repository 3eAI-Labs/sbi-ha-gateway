// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nats_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	sbiclient "github.com/3eAI-Labs/sbi-ha-gateway-client"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/nats"
	natsserver "github.com/nats-io/nats-server/v2/server"
	gnats "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var requestSubjects = []string{
	sbiclient.SubjectAuthRequest,
	sbiclient.SubjectAuthConfirm,
	sbiclient.SubjectMobilityRegistration,
	sbiclient.SubjectMobilityQuery,
	sbiclient.SubjectLocationInfo,
	sbiclient.SubjectDataQuery,
	sbiclient.SubjectDataUpdate,
}

// A stream on 5g.> answers every request subject with its publish acknowledgement before
// any application can. Request must report that, not return it as the reply.
func TestRequest_StreamCapturesRequestSubjects(t *testing.T) {
	s := runServer(&natsserver.Options{Port: -1, JetStream: true, StoreDir: t.TempDir()})
	defer s.Shutdown()

	client, err := nats.NewClient(s.ClientURL(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Without the stream, the application's reply comes back.
	sub, err := client.GetConn().Subscribe("5g.>", func(m *gnats.Msg) {
		_ = m.Respond([]byte(`{"stream":"S","seq":1,"supi":"imsi-001010000000001"}`))
	})
	require.NoError(t, err)
	for _, subject := range requestSubjects {
		reply, err := client.Request(ctx, subject, []byte(`{}`), time.Second)
		require.NoError(t, err, subject)
		assert.Contains(t, string(reply), "imsi-001010000000001", subject)
	}
	require.NoError(t, sub.Unsubscribe())

	js, err := client.JetStream()
	require.NoError(t, err)
	_, err = js.CreateStream(ctx, jetstream.StreamConfig{Name: "CORE_EVENTS", Subjects: []string{"5g.>"}})
	require.NoError(t, err)

	for _, subject := range requestSubjects {
		reply, err := client.Request(ctx, subject, []byte(`{}`), time.Second)
		assert.ErrorIs(t, err, nats.ErrJetStreamReply, subject)
		assert.ErrorContains(t, err, `"CORE_EVENTS"`, subject)
		assert.Nil(t, reply, subject)
	}
}
