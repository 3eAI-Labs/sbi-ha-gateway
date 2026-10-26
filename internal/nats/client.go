// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nats

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type INatsClient interface {
	Request(ctx context.Context, subject string, data []byte, timeout time.Duration) ([]byte, error)
	Publish(subject string, data []byte) error
	IsConnected() bool
	GetConn() *nats.Conn
	Close()
}

type Client struct {
	conn *nats.Conn
	log  *slog.Logger

	// js is lazily initialised on first JetStream() call. It is not opened at connect time:
	// only the SMS surfaces (SMS_ENABLED) use JetStream, and a deployment without them should
	// not pay the startup cost of probing for a JetStream API.
	js jetstream.JetStream
}

// DefaultConnectTimeout is used when no timeout is provided
const DefaultConnectTimeout = 5 * time.Second

func NewClient(url string, log *slog.Logger) (*Client, error) {
	return NewClientWithTimeout(url, log, DefaultConnectTimeout)
}

func NewClientWithTimeout(url string, log *slog.Logger, connectTimeout time.Duration) (*Client, error) {
	return NewClientWithSecurity(url, log, connectTimeout, Security{})
}

// NewClientWithSecurity connects with sec's authentication and TLS. Settings that
// contradict each other are an error before any connection is attempted.
func NewClientWithSecurity(url string, log *slog.Logger, connectTimeout time.Duration, sec Security) (*Client, error) {
	if connectTimeout == 0 {
		connectTimeout = DefaultConnectTimeout
	}
	secOpts, err := sec.options(url)
	if err != nil {
		return nil, err
	}
	nc, err := nats.Connect(url, append([]nats.Option{
		nats.Name("SBI-Gateway"),
		nats.Timeout(connectTimeout),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Warn("NATS disconnected", slog.Any("error", err))
			metrics.SetNatsConnected(false)
			metrics.RecordNatsEvent("disconnected")
		}),
		// The first connection, also when it is made only after retrying
		// (RetryOnFailedConnect); later ones go to the ReconnectHandler.
		nats.ConnectHandler(func(_ *nats.Conn) {
			metrics.SetNatsConnected(true)
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			log.Info("NATS reconnected")
			metrics.SetNatsConnected(true)
			metrics.RecordNatsEvent("reconnected")
		}),
		// Asynchronous errors, a slow consumer above all: a subscription that fell behind
		// loses the messages NATS could not buffer. Without a handler nats.go drops them unsaid.
		nats.ErrorHandler(func(_ *nats.Conn, sub *nats.Subscription, err error) {
			var subject string
			if sub != nil {
				subject = sub.Subject
			}
			if errors.Is(err, nats.ErrSlowConsumer) {
				metrics.RecordNatsEvent("slow_consumer")
				log.Warn("NATS slow consumer: messages dropped", slog.String("subject", subject))
				return
			}
			metrics.RecordNatsEvent("error")
			log.Warn("NATS error", slog.String("subject", subject), slog.Any("error", err))
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			metrics.SetNatsConnected(false)
		}),
	}, secOpts...)...)
	if err != nil {
		metrics.SetNatsConnected(false)
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}

	// With RetryOnFailedConnect, Connect returns while still reconnecting when no server
	// answered: the gauge must say so.
	metrics.SetNatsConnected(nc.IsConnected())
	return &Client{
		conn: nc,
		log:  log,
	}, nil
}

// Request sends data on subject and waits for the reply, at most timeout (none when
// timeout is 0) and no longer than ctx allows.
func (c *Client) Request(ctx context.Context, subject string, data []byte, timeout time.Duration) ([]byte, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	start := time.Now()
	msg, err := c.conn.RequestWithContext(ctx, subject, data)
	duration := time.Since(start).Seconds()

	if err != nil {
		status := "error"
		switch {
		case errors.Is(err, context.DeadlineExceeded), errors.Is(err, nats.ErrTimeout):
			status = "timeout"
		case errors.Is(err, nats.ErrNoResponders):
			status = "no_responders"
		}
		metrics.RecordNatsRequest(subject, status, duration)
		return nil, err
	}
	if stream, ok := jetStreamPublishReply(msg.Data); ok {
		metrics.RecordNatsRequest(subject, "jetstream_reply", duration)
		return nil, fmt.Errorf("%w: stream %q captures subject %q", ErrJetStreamReply, stream, subject)
	}

	metrics.RecordNatsRequest(subject, "success", duration)
	return msg.Data, nil
}

// ErrJetStreamReply is returned by Request when the reply came from JetStream, not from an
// application. A stream that captures a request subject stores the request and answers
// it with its publish acknowledgement (or a publish error) at once; the application's own
// reply, if it sends one, arrives too late or goes to a JetStream subject. Treating the
// acknowledgement as the application's reply would answer the network function with a
// success that never happened.
var ErrJetStreamReply = errors.New("reply came from JetStream, not from the application")

// jetStreamKeys are the members of a JetStream publish response (nats-server
// JSPubAckResponse: PubAck plus error). Every such response names the stream.
var jetStreamKeys = map[string]bool{"stream": true, "seq": true, "domain": true, "duplicate": true, "error": true}

// jetStreamPublishReply reports whether data is a JetStream publish response, and the
// stream it names: a JSON object with a string "stream" and no member a publish response
// does not have. An application reply with a "stream" member among others is not one.
func jetStreamPublishReply(data []byte) (string, bool) {
	if !bytes.Contains(data, []byte(`"stream"`)) {
		return "", false
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return "", false
	}
	for k := range members {
		if !jetStreamKeys[k] {
			return "", false
		}
	}
	var stream string
	if err := json.Unmarshal(members["stream"], &stream); err != nil || stream == "" {
		return "", false
	}
	return stream, true
}

func (c *Client) Publish(subject string, data []byte) error {
	return c.conn.Publish(subject, data)
}

func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *Client) IsConnected() bool {
	return c.conn.Status() == nats.CONNECTED
}

func (c *Client) GetConn() *nats.Conn {
	return c.conn
}

// JetStream returns a JetStream context, lazily initialising on first call.
// Subsequent calls reuse the same instance. Errors only on the very first
// call (probe of $JS.API.INFO via the underlying conn).
func (c *Client) JetStream() (jetstream.JetStream, error) {
	if c.js != nil {
		return c.js, nil
	}
	js, err := jetstream.New(c.conn)
	if err != nil {
		return nil, fmt.Errorf("init JetStream: %w", err)
	}
	c.js = js
	return js, nil
}
