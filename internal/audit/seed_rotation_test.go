package audit

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/config"
)

// The chain key cannot be recomputed from the audit salt, which sits in a
// readable file: a chain written under the KEK-derived seed does not verify
// under the salt, and different secrets give different seeds.
func TestAuditKeyNotFromSaltAlone(t *testing.T) {
	salt := bytes.Repeat([]byte{5}, 32)
	secretA := bytes.Repeat([]byte{1}, 32)
	secretB := bytes.Repeat([]byte{2}, 32)

	seedA, seedB := ChainSeed(secretA, salt), ChainSeed(secretB, salt)
	if bytes.Equal(seedA, seedB) || bytes.Equal(seedA, salt) {
		t.Fatal("chain seed does not depend on the secret")
	}
	if bytes.Equal(DeriveChainMACKey(seedA), DeriveChainMACKey(salt)) {
		t.Fatal("chain MAC key equals the salt-only derivation")
	}

	dir := filepath.Join(t.TempDir(), "cfg")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "audit.log")
	l, err := Open(path, seedA, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := l.Log(context.Background(), Event{Action: ActionRead, Outcome: OutcomeOK}); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.Close()

	if r, err := VerifyChain(path, seedA, nil); err != nil || r.FirstBadLine != 0 {
		t.Fatalf("chain under its own seed: %v %+v", err, r)
	}
	// An attacker who can read the salt recomputes the chain with it and
	// cannot make the log verify.
	if r, err := VerifyChain(path, salt, nil); err != nil || r.FirstBadLine == 0 {
		t.Fatalf("chain verified under the salt alone: %v %+v", err, r)
	}
}

func TestNumberedRotation(t *testing.T) {
	if got := LoadRetainFiles(config.AuditConfig{}); got != 20 {
		t.Fatalf("default retained files = %d, want 20", got)
	}
	if got := LoadRetainFiles(config.AuditConfig{RetainFiles: 7}); got != 7 {
		t.Fatalf("configured retained files = %d, want 7", got)
	}
	if got := LoadRetentionDays(config.AuditConfig{}); got != 365 {
		t.Fatalf("default retention = %d days, want 365", got)
	}
	if got := LoadRetentionDays(config.AuditConfig{RetentionDays: 30, RetainDays: 90}); got != 90 {
		t.Fatalf("retain_days must win over retention_days, got %d", got)
	}

	l, path, _ := openSmallLog(t, 1, 20)
	l.SetRetainFiles(4)
	for range 12 {
		if err := l.Log(context.Background(), Event{Action: ActionRead, Outcome: OutcomeOK}); err != nil {
			t.Fatal(err)
		}
	}
	for g := 1; g <= 4; g++ {
		if _, err := os.Stat(rotatedName(path, g)); err != nil {
			t.Fatalf("generation %d missing: %v", g, err)
		}
	}
	if _, err := os.Stat(rotatedName(path, 5)); !os.IsNotExist(err) {
		t.Fatalf("generation beyond retain_files kept: %v", err)
	}
	if maxLogSize != 5*1024*1024 {
		t.Fatalf("rotation size = %d, want 5 MiB", maxLogSize)
	}
}

func TestRetireLogMovesAChainUnderAnotherKey(t *testing.T) {
	l, path, _ := openSmallLog(t, 1<<20, 3)
	if err := l.Log(context.Background(), Event{Action: ActionRead, Outcome: OutcomeOK}); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	if err := RetireLog(path, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("log still in place: %v", err)
	}
	if _, err := os.Stat(rotatedName(path, 1)); err != nil {
		t.Fatalf("retired log missing: %v", err)
	}
	if err := RetireLog(path, 3); err != nil {
		t.Fatalf("retiring a missing log: %v", err)
	}
}
