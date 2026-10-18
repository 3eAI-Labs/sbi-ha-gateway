// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package audit

import (
	"strings"
	"testing"
)

func TestMaskSUPI_IMSI(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// MCC=286 (Turkey) — keeps "imsi-286" + ***.
		{"imsi-286010000000001", "imsi-286***"},
		// MCC=234 (UK) — keeps "imsi-234" + ***.
		{"imsi-234150000000001", "imsi-234***"},
		// Edge: too short to even hold an MCC.
		{"imsi-12", "imsi-***"},
		{"imsi-", "imsi-***"},
		// Non-digit MCC prefix (caller bug or attack) — redact entirely.
		{"imsi-A86010000000001", "imsi-***"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got := MaskSUPI(c.in)
			if got != c.want {
				t.Errorf("MaskSUPI(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestMaskSUPI_SUCI_StableHashed(t *testing.T) {
	suci := "suci-0-001-01-0-0-0-12345"
	got := MaskSUPI(suci)
	if !strings.HasPrefix(got, "suci-sha256-") {
		t.Fatalf("expected suci-sha256- prefix; got %q", got)
	}
	// Hash is stable: same input → same output.
	if got != MaskSUPI(suci) {
		t.Error("MaskSUPI must be deterministic")
	}
	// Different SUCI → different hash (not guaranteed by sha256/4-byte but
	// astronomically unlikely for crafted strings; this catches a bug
	// where the function ignores its input).
	if got == MaskSUPI("suci-0-001-01-0-0-0-99999") {
		t.Error("different SUCI inputs must produce different hashes")
	}
}

func TestMaskSUPI_Empty(t *testing.T) {
	if got := MaskSUPI(""); got != "" {
		t.Errorf("empty input must return empty; got %q", got)
	}
}

func TestMaskSUPI_Unknown_ReturnsRedacted(t *testing.T) {
	cases := []string{
		"nai:user@operator.com",
		"random-string",
		"IMSI-286010000000001", // wrong case — defensive: no fuzzy match
	}
	for _, in := range cases {
		got := MaskSUPI(in)
		if got != "supi-redacted" {
			t.Errorf("MaskSUPI(%q) = %q, want supi-redacted", in, got)
		}
	}
}

// MaskSUPI must NEVER return its input verbatim — that's the security
// invariant the entire audit pipeline depends on. This guards against a
// future refactor that adds a "passthrough on unknown" path.
func TestMaskSUPI_NeverReturnsRawInput(t *testing.T) {
	cases := []string{
		"imsi-286010000000001",
		"suci-0-001-01-0-0-0-12345",
		"random",
		"imsi-",
	}
	for _, in := range cases {
		if MaskSUPI(in) == in {
			t.Errorf("MaskSUPI returned raw input for %q — leak invariant violated", in)
		}
	}
}
