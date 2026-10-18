// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nats

import (
	"encoding/json"
	"log/slog"

	"github.com/nats-io/nats.go"
)

type Publisher struct {
	conn *nats.Conn
	log  *slog.Logger
}

func NewPublisher(conn *nats.Conn, log *slog.Logger) *Publisher {
	return &Publisher{
		conn: conn,
		log:  log,
	}
}

// PublishEvent publishes a domain event to the NATS JetStream or Core NATS
func (p *Publisher) PublishEvent(subject string, event interface{}) error {
	data, err := json.Marshal(event)
	if err != nil {
		p.log.Error("Failed to marshal event", slog.Any("error", err))
		return err
	}

	p.log.Debug("Publishing event", slog.String("subject", subject))
	return p.conn.Publish(subject, data)
}
