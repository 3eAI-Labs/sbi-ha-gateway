// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

// Package outbound provides the gateway-as-SBI-client surface.
//
// Direction: NATS event/internal trigger -> Gateway -> external 5G NF
// (inverse of the inbound handlers under internal/handlers/*.go).
//
// Profile selects the delivery transport:
//   - ProfileSBIDirect: native HTTP/2 SBI call to the target NF (uses sbi.AmfClient).
//   - ProfileSCEFRest:  out-of-band delivery via SCEF REST; this package is bypassed.
//
// The profile is fixed per gateway instance via OUTBOUND_PROFILE env var.
package outbound

import "fmt"

// Profile selects how outbound 5G signalling is delivered.
type Profile string

const (
	// ProfileSBIDirect routes via the native HTTP/2 SBI client.
	ProfileSBIDirect Profile = "sbi_direct"

	// ProfileSCEFRest defers delivery to the SCEF REST adapter.
	// Outbound calls return ErrBypassed; callers must not treat this as a failure.
	ProfileSCEFRest Profile = "scef_rest"

	// ProfileMtcIwfRest is the MTC-IWF (Machine-Type Communications IWF)
	// REST profile. Operator peering decision pending; selecting this
	// profile causes Send to return ErrMtcIwfNotImplemented at call time
	// (NOT at startup) so the gateway can boot in a partially-provisioned
	// 5GC and fail loudly only when traffic actually targets MTC-IWF.
	ProfileMtcIwfRest Profile = "mtc_iwf_rest"

	// ProfileScefRestHTTPS is the SCEF REST profile over HTTPS, distinct
	// from ProfileSCEFRest (which is the existing bypass mode where an
	// external SCEF adapter handles delivery off-band). Operator peering
	// pending — Send returns ErrScefNotImplemented.
	ProfileScefRestHTTPS Profile = "scef_rest_https"
)

// Validate returns an error if p is not a recognised profile.
func (p Profile) Validate() error {
	switch p {
	case ProfileSBIDirect, ProfileSCEFRest, ProfileMtcIwfRest, ProfileScefRestHTTPS:
		return nil
	default:
		return fmt.Errorf("outbound: unknown profile %q", p)
	}
}
