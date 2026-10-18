// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/sbi"
)

// New returns a Client for the given profile.
// Returns an error if the profile is unknown.
//
// httpClient is only used by the sbi_direct profile; pass nil to use defaults.
func New(profile Profile, httpClient *sbi.AmfClient) (Client, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	switch profile {
	case ProfileSBIDirect:
		return NewSBIDirect(httpClient), nil
	case ProfileSCEFRest:
		return NewSCEFRest(), nil
	case ProfileMtcIwfRest:
		return notImplementedClient{prof: ProfileMtcIwfRest, err: ErrMtcIwfNotImplemented}, nil
	case ProfileScefRestHTTPS:
		return notImplementedClient{prof: ProfileScefRestHTTPS, err: ErrScefNotImplemented}, nil
	}
	// Unreachable thanks to Validate(), but keep the compiler happy.
	return nil, nil
}
