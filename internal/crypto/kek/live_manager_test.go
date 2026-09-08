package kek_test

// live_manager_test.go exercises OPKEK/BWKEK against a REAL, installed
// op/bw CLI and a real signed-in manager session. Every test here is
// skipped unless explicitly opted in — ordinary `go test ./...` (and CI)
// must never discover or invoke an installed password-manager binary
// (F47). Run manually against disposable test vault items:
//
//	KEYLATCH_LIVE_MANAGER_TESTS=1 \
//	KEYLATCH_LIVE_OP_VAULT=... KEYLATCH_LIVE_OP_ITEM=... KEYLATCH_LIVE_OP_FIELD=... \
//	go test ./internal/crypto/kek/... -run Live
//
//	KEYLATCH_LIVE_MANAGER_TESTS=1 BW_SESSION=... \
//	KEYLATCH_LIVE_BW_ITEM=... KEYLATCH_LIVE_BW_FIELD=... \
//	go test ./internal/crypto/kek/... -run Live

import (
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/kek"
)

func skipUnlessLiveManagerTestsEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv("KEYLATCH_LIVE_MANAGER_TESTS") != "1" {
		t.Skip("set KEYLATCH_LIVE_MANAGER_TESTS=1 to run against a real installed manager CLI")
	}
}

func TestOPKEK_LiveRoundTrip(t *testing.T) {
	skipUnlessLiveManagerTestsEnabled(t)

	vault := os.Getenv("KEYLATCH_LIVE_OP_VAULT")
	item := os.Getenv("KEYLATCH_LIVE_OP_ITEM")
	field := os.Getenv("KEYLATCH_LIVE_OP_FIELD")
	if vault == "" || item == "" || field == "" {
		t.Skip("KEYLATCH_LIVE_OP_VAULT, KEYLATCH_LIVE_OP_ITEM, and KEYLATCH_LIVE_OP_FIELD must all be set")
	}

	k, err := kek.OPKEK(vault, item, field)
	if err != nil {
		t.Fatalf("OPKEK: %v", err)
	}

	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 1)
	}
	wrapped, err := k.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	got, err := k.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if string(got) != string(dek) {
		t.Fatal("round-trip mismatch")
	}
}

func TestBWKEK_LiveRoundTrip(t *testing.T) {
	skipUnlessLiveManagerTestsEnabled(t)

	if os.Getenv("BW_SESSION") == "" {
		t.Skip("BW_SESSION must be set to a real, unlocked Bitwarden session")
	}
	item := os.Getenv("KEYLATCH_LIVE_BW_ITEM")
	field := os.Getenv("KEYLATCH_LIVE_BW_FIELD")
	if item == "" || field == "" {
		t.Skip("KEYLATCH_LIVE_BW_ITEM and KEYLATCH_LIVE_BW_FIELD must both be set")
	}

	k, err := kek.BWKEK(item, field)
	if err != nil {
		t.Fatalf("BWKEK: %v", err)
	}

	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 2)
	}
	wrapped, err := k.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	got, err := k.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if string(got) != string(dek) {
		t.Fatal("round-trip mismatch")
	}
}
