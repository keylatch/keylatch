//go:build darwin

package keychain_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/keychain"
	kexec "github.com/keylatch/keylatch/internal/exec"
)

// countUnlockItemWrites returns the number of add-generic-password calls
// that targeted the login-keychain unlock item (service "keylatch-keychain",
// account "unlock") — the item that must never be silently regenerated with
// a new password on a re-run (C1).
func countUnlockItemWrites(calls []kexec.MockCall) int {
	n := 0
	for _, call := range calls {
		if len(call.Args) == 0 || call.Args[0] != "add-generic-password" {
			continue
		}
		isUnlockItem := false
		for _, a := range call.Args {
			if a == "keylatch-keychain" {
				isUnlockItem = true
				break
			}
		}
		if isUnlockItem {
			n++
		}
	}
	return n
}

// TestInit_Idempotent_SecondRunReusesPasswordAndKeepsSecretsReadable is the
// C1 regression test: Init() must not corrupt keychain access when run a
// second time (e.g. on `keylatch setup` re-run). Before the fix, every Init()
// call generated a brand-new random password and unconditionally upserted
// the login-keychain unlock item, orphaning any secrets stored under the
// previous (never-persisted) password.
func TestInit_Idempotent_SecondRunReusesPasswordAndKeepsSecretsReadable(t *testing.T) {
	tmpDir := t.TempDir()
	keychainPath := filepath.Join(tmpDir, "test-init.keychain-db")
	lockPath := filepath.Join(tmpDir, "test-init.keychain.lock")
	secBin := "/usr/bin/security"

	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			// Existing login-keychain unlock item — simulates state left by a
			// prior successful Init() (or, on the very first call here, a
			// stale item from a previous install with no keychain-db yet).
			secBin + "|find-generic-password|-s|keylatch-keychain|-a|unlock|-w": {
				Stdout: []byte("existing-unlock-pw\n"),
			},
			secBin + "|unlock-keychain|-p|existing-unlock-pw|" + keychainPath: {},
			secBin + "|lock-keychain|" + keychainPath:                         {},
			// Manifest starts empty (no items yet).
			secBin + "|find-generic-password|-s|keylatch-_manifest|-a|manifest|-w|-k|" + keychainPath: {
				ExitCode: 44,
			},
		},
	}

	b, err := keychain.Open(keychain.Options{
		KeychainPath: keychainPath,
		LockPath:     lockPath,
		SecurityBin:  secBin,
		Runner:       runner,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	ctx := context.Background()

	// --- First run ---
	// No keychain-db file exists on disk yet, so this exercises the
	// "stale unlock item, no db yet" branch: reuse the existing password to
	// create the (currently empty) keychain-db. Nothing is at risk of being
	// orphaned because no keychain-db data exists yet.
	if err := b.Init(ctx, "default"); err != nil {
		t.Fatalf("first Init: %v", err)
	}
	firstRunUnlockWrites := countUnlockItemWrites(runner.CallsCopy())
	if firstRunUnlockWrites == 0 {
		t.Fatalf("first Init: expected at least one write to the unlock item (fresh db case), got 0")
	}

	// MockRunner never touches the filesystem — simulate that create-keychain
	// actually produced a real db file, as it would in production.
	if err := os.WriteFile(keychainPath, []byte("fake-keychain-db"), 0o600); err != nil {
		t.Fatalf("simulate keychain-db creation: %v", err)
	}

	// Store a secret via the now-"initialized" backend.
	secretPath := "default/openrouter/api_key"
	meta := backend.Meta{Path: secretPath, Backend: "keychain", Version: 1}
	if err := b.Set(ctx, secretPath, []byte("sk-test-value"), meta); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// MockRunner is stateless (canned responses only) — simulate that Set
	// persisted the manifest and value, so a later Get can observe them.
	runner.Responses[secBin+"|find-generic-password|-s|keylatch-_manifest|-a|manifest|-w|-k|"+keychainPath] = kexec.MockResponse{
		Stdout: []byte(`{"version":1,"items":[{"connection":"openrouter","fields":["api_key"]}]}`),
	}
	runner.Responses[secBin+"|find-generic-password|-s|keylatch-openrouter|-a|api_key|-w|-k|"+keychainPath] = kexec.MockResponse{
		Stdout: []byte("sk-test-value\n"),
	}

	// Reset call history so the assertions below are scoped to the SECOND
	// Init() call only.
	runner.Reset()

	// --- Second run ---
	// The keychain-db now exists on disk, and the existing (mocked) unlock
	// password successfully unlocks it — Init must treat this as a
	// verify/no-op for the unlock item: reuse the password, do not generate
	// a new one.
	if err := b.Init(ctx, "default"); err != nil {
		t.Fatalf("second Init: %v", err)
	}

	secondRunUnlockWrites := countUnlockItemWrites(runner.CallsCopy())
	// RepairACL always re-issues the unlock item's ACL (idempotently,
	// preserving the password value it read) — that accounts for exactly one
	// write. The FIRST run additionally performs a dedicated password-store
	// write (writeUnlockItem=true), so it has strictly more unlock-item
	// writes than the second run, which must skip that dedicated write
	// entirely (writeUnlockItem=false) once the existing password verifies.
	if secondRunUnlockWrites >= firstRunUnlockWrites {
		t.Errorf("second Init: expected fewer unlock-item writes than the first run (no fresh password generated/stored), got first=%d second=%d",
			firstRunUnlockWrites, secondRunUnlockWrites)
	}

	// The secret stored before the second Init() must still be readable —
	// this is the core C1 data-loss assertion: a re-run must never orphan
	// existing secrets.
	value, _, err := b.Get(ctx, secretPath)
	if err != nil {
		t.Fatalf("Get after second Init: %v", err)
	}
	if string(value) != "sk-test-value" {
		t.Errorf("Get after second Init: got %q, want %q", value, "sk-test-value")
	}
}

// TestInit_RefusesToRegeneratePassword_WhenExistingItemDoesNotUnlockDB
// verifies the fail-closed refusal path (C1): when a keychain-db exists but
// the login-keychain unlock item does not successfully unlock it, Init must
// refuse to generate a replacement password rather than silently
// orphaning the existing secrets. ForceReinit should proceed anyway.
func TestInit_RefusesToRegeneratePassword_WhenExistingItemDoesNotUnlockDB(t *testing.T) {
	tmpDir := t.TempDir()
	keychainPath := filepath.Join(tmpDir, "test-mismatch.keychain-db")
	lockPath := filepath.Join(tmpDir, "test-mismatch.keychain.lock")
	secBin := "/usr/bin/security"

	// Simulate a keychain-db that already exists on disk.
	if err := os.WriteFile(keychainPath, []byte("fake-keychain-db"), 0o600); err != nil {
		t.Fatalf("simulate keychain-db creation: %v", err)
	}

	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			secBin + "|find-generic-password|-s|keylatch-keychain|-a|unlock|-w": {
				Stdout: []byte("stale-pw\n"),
			},
			// The stale password fails to unlock the existing db.
			secBin + "|unlock-keychain|-p|stale-pw|" + keychainPath: {
				ExitCode: 51, // errSecAuthFailed
				Stderr:   []byte("errSecAuthFailed"),
			},
		},
	}

	b, err := keychain.Open(keychain.Options{
		KeychainPath: keychainPath,
		LockPath:     lockPath,
		SecurityBin:  secBin,
		Runner:       runner,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	ctx := context.Background()

	if err := b.Init(ctx, "default"); err == nil {
		t.Error("Init: expected refusal error when existing unlock item does not match the keychain-db, got nil")
	}

	// No add-generic-password call should have been made — Init must refuse
	// before attempting to write anything.
	if n := countUnlockItemWrites(runner.CallsCopy()); n != 0 {
		t.Errorf("Init (refusal path): expected zero unlock-item writes, got %d", n)
	}
}

// TestInit_ChmodsKeychainDBTo0600 is the M10 regression test: `security
// create-keychain` creates the keychain-db file with the process's
// umask-derived default permissions, which can be as loose as 0644
// (world-readable). Init must force the file to 0600 every time it runs —
// including on the "verify/no-op" re-run path exercised here, so that
// re-running `keylatch keychain-init` also repairs a keychain-db that was
// left with loose permissions by an earlier, unpatched binary.
func TestInit_ChmodsKeychainDBTo0600(t *testing.T) {
	tmpDir := t.TempDir()
	keychainPath := filepath.Join(tmpDir, "test-chmod.keychain-db")
	lockPath := filepath.Join(tmpDir, "test-chmod.keychain.lock")
	secBin := "/usr/bin/security"

	// Simulate a keychain-db that already exists on disk with loose,
	// world-readable permissions — e.g. left over from a prior
	// `security create-keychain` call that ran under a permissive umask.
	if err := os.WriteFile(keychainPath, []byte("fake-keychain-db"), 0o644); err != nil {
		t.Fatalf("seed keychain-db: %v", err)
	}

	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			secBin + "|find-generic-password|-s|keylatch-keychain|-a|unlock|-w": {
				Stdout: []byte("existing-unlock-pw\n"),
			},
			secBin + "|unlock-keychain|-p|existing-unlock-pw|" + keychainPath: {},
			secBin + "|lock-keychain|" + keychainPath:                         {},
			// No manifest yet.
			secBin + "|find-generic-password|-s|keylatch-_manifest|-a|manifest|-w|-k|" + keychainPath: {
				ExitCode: 44,
			},
		},
	}

	b, err := keychain.Open(keychain.Options{
		KeychainPath: keychainPath,
		LockPath:     lockPath,
		SecurityBin:  secBin,
		Runner:       runner,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := b.Init(context.Background(), "default"); err != nil {
		t.Fatalf("Init: %v", err)
	}

	info, statErr := os.Stat(keychainPath)
	if statErr != nil {
		t.Fatalf("stat keychain-db after Init: %v", statErr)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("keychain-db permissions after Init: got %o, want %o", got, 0o600)
	}
}
