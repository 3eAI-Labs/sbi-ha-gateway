// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package uecm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestEmptyResolver_AlwaysNotFound(t *testing.T) {
	r := NewEmpty()
	for _, msisdn := range []string{"905551234567", "", "garbage"} {
		_, err := r.Resolve(context.Background(), msisdn)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("Resolve(%q) = %v, want ErrNotFound", msisdn, err)
		}
	}
}

func writeFile(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "resolver.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNewFromFile_EmptyPath_ReturnsEmpty(t *testing.T) {
	r, err := NewFromFile("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(context.Background(), "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("empty-path resolver should always NotFound, got %v", err)
	}
}

func TestNewFromFile_HappyPath(t *testing.T) {
	path := writeFile(t, `{
		"905551234567": {"Supi": "imsi-286010000000001", "SmsfFqdn": "smsf-1.5gc.tr", "SmsfPlmnId": "28601"},
		"905557654321": {"Supi": "imsi-286010000000002", "SmsfFqdn": "smsf-2.5gc.tr", "SmsfPlmnId": "28601"},
		"905550000003": {"Supi": "imsi-286010000000003", "smsfInstanceId": "6b2f9c1e-4d3a-4f7b-8e5c-2a9d1f0b3c4e", "SmsfPlmnId": "28601"}
	}`)
	r, err := NewFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := r.Resolve(context.Background(), "905551234567")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.Supi != "imsi-286010000000001" || c.SmsfFqdn != "smsf-1.5gc.tr" {
		t.Errorf("got %+v", c)
	}
	// An SMSF known by its instance ID alone: the gateway discovers it.
	c, err = r.Resolve(context.Background(), "905550000003")
	if err != nil || c.SmsfInstanceId != "6b2f9c1e-4d3a-4f7b-8e5c-2a9d1f0b3c4e" || c.SmsfFqdn != "" {
		t.Errorf("got %+v, %v", c, err)
	}
}

func TestNewFromFile_MissingMsisdn_NotFound(t *testing.T) {
	path := writeFile(t, `{"905551234567": {"Supi": "x", "SmsfFqdn": "y"}}`)
	r, _ := NewFromFile(path)
	_, err := r.Resolve(context.Background(), "999")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestNewFromFile_MalformedJSON_FailsAtStartup(t *testing.T) {
	path := writeFile(t, `not json`)
	if _, err := NewFromFile(path); err == nil {
		t.Fatal("malformed JSON must fail at startup, not at resolve time")
	}
}

func TestNewFromFile_EntryMissingFields_FailsAtStartup(t *testing.T) {
	cases := []string{
		`{"905551234567": {"SmsfFqdn": "y"}}`, // Supi missing
		`{"905551234567": {"Supi": "x"}}`,     // SmsfFqdn and SmsfInstanceId missing
	}
	for _, body := range cases {
		path := writeFile(t, body)
		if _, err := NewFromFile(path); err == nil {
			t.Errorf("entry %q should fail validation at startup", body)
		}
	}
}

func TestFileResolver_DefensiveCopy(t *testing.T) {
	path := writeFile(t, `{"x": {"Supi": "s", "SmsfFqdn": "f", "SmsfPlmnId": "p"}}`)
	r, _ := NewFromFile(path)
	got, _ := r.Resolve(context.Background(), "x")
	got.Supi = "MUTATED"
	// Second lookup must still return the original — the resolver hands
	// out copies, not pointers into the live catalogue.
	got2, _ := r.Resolve(context.Background(), "x")
	if got2.Supi != "s" {
		t.Errorf("catalogue mutated through returned pointer: got %q", got2.Supi)
	}
}

func TestNewFromFile_NonexistentPath(t *testing.T) {
	if _, err := NewFromFile("/does/not/exist/resolver.json"); err == nil {
		t.Fatal("missing file path must fail at startup")
	}
}
