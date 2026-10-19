// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"context"
	"errors"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/sbi"
)

// ErrBypassed signals that the configured profile does not deliver via this
// package. Callers must treat it as a no-op success, not as a failure to retry.
var ErrBypassed = errors.New("outbound: bypassed by profile")

// ErrMtcIwfNotImplemented and ErrScefNotImplemented signal that a profile
// is wired into the factory but the underlying transport is awaiting an
// operator peering decision. These are NOT bypass errors — callers should
// surface them as configuration faults (typically with retry=false), so
// dashboards can distinguish "operator hasn't peered yet" from "transport
// is misbehaving".
var (
	ErrMtcIwfNotImplemented = errors.New("outbound: mtc_iwf_rest profile not implemented (operator peering pending)")
	ErrScefNotImplemented   = errors.New("outbound: scef_rest_https profile not implemented (operator peering pending)")
)

// Request describes a single outbound SBI call.
//
// The fields are deliberately a superset so a single Client interface can serve
// notification pushes (DataChange, EE, MT) without a per-service interface.
// Concrete implementations decide which fields are mandatory for their flow.
type Request struct {
	// TargetNF is the destination 5G network function id (AMF, SMF, NEF, ...).
	// Used for discovery in profiles that do their own NF resolution.
	TargetNF string

	// CallbackURI is the absolute URI on the target NF when known
	// (e.g. amf3GppRegistration.deregCallbackUri). When empty, the
	// implementation must resolve via NRF or static map.
	CallbackURI string

	// Service identifies the 3GPP service (e.g. "namf-comm", "nsmf-pdusession").
	Service string

	// Operation is the service operation (e.g. "N1MessageNotify").
	Operation string

	// Payload is the JSON-marshalable body to send.
	Payload interface{}

	// Multipart, when set, is the body instead of Payload: a multipart/related message of
	// a JSON part and a binary part (e.g. Nsmsf_SMService MtForwardSm).
	Multipart *sbi.Multipart

	// Headers carries optional per-call HTTP headers (e.g. 3gpp-Sbi-Sender-Timestamp).
	Headers map[string]string
}

// Response carries delivery metadata. Body is omitted on bypass.
type Response struct {
	StatusCode int
	Body       []byte
	// Multipart is the response's parts when the request was multipart.
	Multipart *sbi.Multipart
}

// Client is the contract every outbound profile must satisfy.
//
// Implementations are expected to be safe for concurrent use.
//
// Send returns:
//   - (resp, nil)            on successful delivery,
//   - (nil, ErrBypassed)     when the active profile delegates elsewhere,
//   - (nil, other error)     on transport / target NF failure (caller may retry).
type Client interface {
	Send(ctx context.Context, req *Request) (*Response, error)

	// Profile returns the profile this client implements; useful for metrics
	// and structured logs without leaking concrete type names.
	Profile() Profile
}
