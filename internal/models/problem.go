// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

// Package models holds the gateway's own HTTP types. The types that also travel over NATS
// are in the wire-contract module, github.com/3eAI-Labs/sbi-ha-gateway-client.
package models

// ProblemDetails represents the RFC 7807 problem details for HTTP APIs.
// Defined in 3GPP TS 29.571 clause 5.2.4.1
type ProblemDetails struct {
	Type     string `json:"type,omitempty"`
	Title    string `json:"title,omitempty"`
	Status   int    `json:"status,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
	Cause    string `json:"cause,omitempty"` // 3GPP specific
	// InvalidParams names the invalid parameters (TS 29.571 InvalidParam).
	InvalidParams []InvalidParam `json:"invalidParams,omitempty"`
}

// InvalidParam is TS 29.571 InvalidParam. For a URI variable, Param is its name with
// braces, "{supi}".
type InvalidParam struct {
	Param  string `json:"param"`
	Reason string `json:"reason,omitempty"`
}
