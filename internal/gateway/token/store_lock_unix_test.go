//go:build !windows

package token

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWithStoreLock_RunsUnderLock(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "tokens.json")
	ran := false
	if err := withStoreLock(storePath, func() error {
		ran = true
		return nil
	}); err != nil {
		t.Fatalf("withStoreLock: %v", err)
	}
	if !ran {
		t.Fatal("fn did not run")
	}
}

func TestWithStoreLock_DoesNotRunUnlocked(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ran := false
	err := withStoreLock(filepath.Join(blocker, "tokens.json"), func() error {
		ran = true
		return nil
	})
	if err == nil {
		t.Fatal("expected an error when the lock file cannot be created")
	}
	if ran {
		t.Fatal("fn must not run without the lock")
	}
}
