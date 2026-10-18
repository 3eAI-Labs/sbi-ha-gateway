// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package logger

import (
	"log/slog"
	"os"
)

// Global logger instance (initialized with JSON by default)
var defaultLogger *slog.Logger

func init() {
	// Default initialization to prevent nil pointer if InitLogger isn't called
	handler := slog.NewJSONHandler(os.Stdout, nil)
	defaultLogger = slog.New(handler)
	slog.SetDefault(defaultLogger)
}

// InitLogger configures a JSON logger for production, logging at level and above, and
// sets it as default
func InitLogger(serviceName string, level slog.Level) *slog.Logger {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}).WithAttrs([]slog.Attr{
		slog.String("service", serviceName),
	})

	defaultLogger = slog.New(handler)
	slog.SetDefault(defaultLogger)
	return defaultLogger
}

// Info logs at LevelInfo
func Info(msg string, args ...any) {
	slog.Info(msg, args...)
}

// Error logs at LevelError
func Error(msg string, err error, args ...any) {
	if err != nil {
		args = append(args, slog.Any("error", err))
	}
	slog.Error(msg, args...)
}

// Warn logs at LevelWarn
func Warn(msg string, args ...any) {
	slog.Warn(msg, args...)
}

// Debug logs at LevelDebug
func Debug(msg string, args ...any) {
	slog.Debug(msg, args...)
}

// String is a helper for slog.String
func String(key, value string) slog.Attr {
	return slog.String(key, value)
}

// Int is a helper for slog.Int
func Int(key string, value int) slog.Attr {
	return slog.Int(key, value)
}

// Any is a helper for slog.Any
func Any(key string, value any) slog.Attr {
	return slog.Any(key, value)
}
