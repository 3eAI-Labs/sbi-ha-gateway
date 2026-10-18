// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package handlers_test

import (
	"context"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/mock"
)

type MockNatsClient struct {
	mock.Mock
}

func (m *MockNatsClient) Request(ctx context.Context, subject string, data []byte, timeout time.Duration) ([]byte, error) {
	args := m.Called(ctx, subject, data, timeout)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockNatsClient) Publish(subject string, data []byte) error {
	args := m.Called(subject, data)
	return args.Error(0)
}

func (m *MockNatsClient) IsConnected() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockNatsClient) GetConn() *nats.Conn {
	return nil
}

func (m *MockNatsClient) Close() {
	m.Called()
}
