// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// MaskSUPI returns an audit-safe rendering of a 5G subscriber identity per
// 3GPP TS 23.003 §2.2A and §28.7. Two SUPI flavours occur in NF traffic:
//
//   - imsi-<MCC><MNC><MSIN>  → preserve "imsi-<MCC><MNC>" routing prefix,
//     mask the MSIN with "***". Operators correlate
//     by PLMN; subscriber identity stays redacted.
//
//   - suci-<scheme>-<MCC>-<MNC>-...-<encrypted>  → return the SHA-256/8 of
//     the full SUCI as "suci-sha256-<8hex>". This
//     lets dedup/correlation work without storing
//     any SUCI field, including the routing
//     indicator that could itself be PII-adjacent.
//
// Anything that doesn't match either prefix returns "supi-redacted" — never
// the raw input. Defensive: an unknown SUPI shape from an upstream change
// must not silently leak through audit.
//
// Empty input returns "" (nothing to mask).
func MaskSUPI(supi string) string {
	if supi == "" {
		return ""
	}
	switch {
	case strings.HasPrefix(supi, "imsi-"):
		return maskIMSI(supi)
	case strings.HasPrefix(supi, "suci-"):
		return hashSUCI(supi)
	default:
		return "supi-redacted"
	}
}

// maskIMSI keeps "imsi-" + the MCC (first 3 digits per TS 23.003 §2.2) and
// masks everything after. MNC length is per-PLMN (2 or 3 digits) and cannot
// be determined from the IMSI alone without a PLMN database — leaking the
// first MSIN digit by guessing the longer form is exactly the failure mode
// audit redaction is supposed to prevent. MCC alone tells the auditor
// "which country/regulator" which is the load-bearing question; finer
// PLMN attribution lives in separate operational metadata, not in the
// SUPI itself.
func maskIMSI(supi string) string {
	digits := strings.TrimPrefix(supi, "imsi-")
	if len(digits) < 3 || !allDigits(digits[:3]) {
		// Too short to even carry an MCC, or the prefix isn't numeric.
		// Redact entirely rather than leak the fragment.
		return "imsi-***"
	}
	return "imsi-" + digits[:3] + "***"
}

// hashSUCI computes a stable, short fingerprint of the entire SUCI. SHA-256
// truncated to 8 hex chars (32 bits) is enough for cross-event correlation
// in normal-volume audit streams without inviting rainbow-table style
// reverse-mapping (a 32-bit space against the full SUCI keyspace is
// astronomically sparse).
func hashSUCI(supi string) string {
	sum := sha256.Sum256([]byte(supi))
	return "suci-sha256-" + hex.EncodeToString(sum[:4])
}

func allDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
