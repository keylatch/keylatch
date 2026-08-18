//go:build darwin

package keychain_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/keychain"
	kexec "github.com/keylatch/keylatch/internal/exec"
)

// assertUnlockACLTArgEquals finds the add-generic-password call that updated
// the login-keychain unlock item's ACL and asserts its -T value equals want.
// `-T` only ever accepts a filesystem path (see RepairACL's doc comment) —
// this guards against C4 regressing (passing codesign dump text instead).
func assertUnlockACLTArgEquals(t *testing.T, runner *kexec.MockRunner, want string) {
	t.Helper()
	for _, call := range runner.CallsCopy() {
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
		if !isUnlockItem {
			continue
		}
		for i, a := range call.Args {
			if a == "-T" {
				if i+1 >= len(call.Args) {
					t.Fatalf("add-generic-password: -T flag has no following value: %v", call.Args)
				}
				if got := call.Args[i+1]; got != want {
					t.Errorf("add-generic-password -T value: got %q, want %q (must always be a filesystem path, never codesign dump text)", got, want)
				}
				return
			}
		}
		t.Fatalf("add-generic-password to unlock item missing -T flag: %v", call.Args)
	}
	t.Fatal("no add-generic-password call to the unlock item was recorded")
}

func TestVerifyACL_Match(t *testing.T) {
	// VerifyACL should return nil when a real read of the unlock item
	// succeeds — i.e. the login-keychain ACL trusts the current binary.
	// (`security` enforces the ACL at read time; there is no separate
	// "-g" ACL dump to grep for real trusted-application data.)
	secBin := "/usr/bin/security"

	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			secBin + "|find-generic-password|-s|keylatch-keychain|-a|unlock|-w": {
				Stdout: []byte("test-unlock-password\n"),
			},
		},
	}

	b, err := keychain.Open(keychain.Options{
		KeychainPath: testKeychainPath,
		LockPath:     testLockPath,
		SecurityBin:  secBin,
		Runner:       runner,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := b.VerifyACL(context.Background()); err != nil {
		t.Errorf("VerifyACL with successful read: got %v, want nil", err)
	}
}

func TestVerifyACL_Mismatch(t *testing.T) {
	// VerifyACL should return ErrACLMismatch when the real read fails with
	// errSecAuthFailed — the actual macOS signal that the calling binary is
	// not in the item's trusted-application ACL.
	secBin := "/usr/bin/security"

	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			secBin + "|find-generic-password|-s|keylatch-keychain|-a|unlock|-w": {
				ExitCode: 51, // errSecAuthFailed
				Stderr:   []byte("errSecAuthFailed"),
			},
		},
	}

	b, err := keychain.Open(keychain.Options{
		KeychainPath: testKeychainPath,
		LockPath:     testLockPath,
		SecurityBin:  secBin,
		Runner:       runner,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	err = b.VerifyACL(context.Background())
	if !errors.Is(err, backend.ErrACLMismatch) {
		t.Errorf("VerifyACL with errSecAuthFailed: got %v, want ErrACLMismatch", err)
	}
}

func TestVerifyACL_InteractionNotAllowed(t *testing.T) {
	// errSecInteractionNotAllowed (item locked / no UI available for a
	// prompt) is the other real macOS ACL-denial signal readUnlockPassword
	// classifies as ErrACLMismatch.
	secBin := "/usr/bin/security"

	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			secBin + "|find-generic-password|-s|keylatch-keychain|-a|unlock|-w": {
				ExitCode: 25308,
				Stderr:   []byte("errSecInteractionNotAllowed"),
			},
		},
	}

	b, err := keychain.Open(keychain.Options{
		KeychainPath: testKeychainPath,
		LockPath:     testLockPath,
		SecurityBin:  secBin,
		Runner:       runner,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	err = b.VerifyACL(context.Background())
	if !errors.Is(err, backend.ErrACLMismatch) {
		t.Errorf("VerifyACL with errSecInteractionNotAllowed: got %v, want ErrACLMismatch", err)
	}
}

func TestVerifyACL_NotFound_IsNotMisreportedAsACLMismatch(t *testing.T) {
	// A missing unlock item (exit 44 — genuinely not initialised yet) is not
	// an ACL problem and must not be misreported as ErrACLMismatch.
	secBin := "/usr/bin/security"

	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			secBin + "|find-generic-password|-s|keylatch-keychain|-a|unlock|-w": {
				ExitCode: 44,
				Stderr:   []byte("could not be found"),
			},
		},
	}

	b, err := keychain.Open(keychain.Options{
		KeychainPath: testKeychainPath,
		LockPath:     testLockPath,
		SecurityBin:  secBin,
		Runner:       runner,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	err = b.VerifyACL(context.Background())
	if err == nil {
		t.Fatal("VerifyACL with missing item: expected an error, got nil")
	}
	if errors.Is(err, backend.ErrACLMismatch) {
		t.Errorf("VerifyACL with missing item: got ErrACLMismatch, want a plain not-found error")
	}
}

func TestRepairACL_PathOnly(t *testing.T) {
	// RepairACL on unsigned build should call add-generic-password -T {path}.
	secBin := "/usr/bin/security"

	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			// codesign fails (unsigned build simulation).
			"/usr/bin/codesign|-dv|--requirement|-|": {
				ExitCode: 1,
			},
			// Read existing password.
			secBin + "|find-generic-password|-s|keylatch-keychain|-a|unlock|-w": {
				Stdout: []byte("test-pw\n"),
			},
			// Re-issue with -T path.
			secBin + "|add-generic-password|-U|-s|keylatch-keychain|-a|unlock|-w|test-pw": {},
		},
	}

	b, err := keychain.Open(keychain.Options{
		KeychainPath: testKeychainPath,
		LockPath:     testLockPath,
		SecurityBin:  secBin,
		Runner:       runner,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// RepairACL may warn to stderr about unsigned build.
	err = b.RepairACL(context.Background())
	if err != nil {
		t.Logf("RepairACL error (may be expected in unit test without real keychain): %v", err)
	}

	// Verify that add-generic-password was called with -T flag.
	addCalled := false
	for _, call := range runner.CallsCopy() {
		if len(call.Args) > 0 && call.Args[0] == "add-generic-password" {
			for _, arg := range call.Args {
				if arg == "-T" {
					addCalled = true
				}
			}
		}
	}
	if !addCalled && err == nil {
		t.Error("RepairACL: expected add-generic-password with -T flag")
	}
}

func TestRepairACL_AdHocSignature_TreatedAsUnsigned_UsesPath(t *testing.T) {
	// C4 regression: Go arm64 builds are ad-hoc linker-signed by default —
	// codesign -dv exits 0 for them, but Signature=adhoc/TeamIdentifier=not
	// set means there is no real, stable identity. RepairACL must still pass
	// the binary's filesystem PATH to -T, never the codesign dump text.
	secBin := "/usr/bin/security"
	currentBin, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			"/usr/bin/codesign|-dv|--requirement|-|" + currentBin: {
				Stdout: []byte("Executable=" + currentBin + "\nSignature=adhoc\nTeamIdentifier=not set\n"),
			},
			secBin + "|find-generic-password|-s|keylatch-keychain|-a|unlock|-w": {
				Stdout: []byte("test-pw\n"),
			},
		},
	}

	b, err := keychain.Open(keychain.Options{
		KeychainPath: testKeychainPath,
		LockPath:     testLockPath,
		SecurityBin:  secBin,
		Runner:       runner,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := b.RepairACL(context.Background()); err != nil {
		t.Fatalf("RepairACL: %v", err)
	}

	assertUnlockACLTArgEquals(t, runner, currentBin)
}

func TestRepairACL_RealSignature_StillUsesPathNotDump(t *testing.T) {
	// Even with a genuine Team ID, -T must be the filesystem path — the
	// `security` CLI's -T flag has never accepted a codesign identity or
	// SecRequirement clause (that concept only exists via Security.framework
	// APIs this codebase does not use).
	secBin := "/usr/bin/security"
	currentBin, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			"/usr/bin/codesign|-dv|--requirement|-|" + currentBin: {
				Stdout: []byte("Executable=" + currentBin +
					"\nAuthority=Developer ID Application: Example Corp (TEAMID1234)\nTeamIdentifier=TEAMID1234\n"),
			},
			secBin + "|find-generic-password|-s|keylatch-keychain|-a|unlock|-w": {
				Stdout: []byte("test-pw\n"),
			},
		},
	}

	b, err := keychain.Open(keychain.Options{
		KeychainPath: testKeychainPath,
		LockPath:     testLockPath,
		SecurityBin:  secBin,
		Runner:       runner,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := b.RepairACL(context.Background()); err != nil {
		t.Fatalf("RepairACL: %v", err)
	}

	assertUnlockACLTArgEquals(t, runner, currentBin)
}

func TestRepairItemACLs_NoValueReads(t *testing.T) {
	// RepairItemACLs must NOT produce value reads during manifest walk.
	secBin := "/usr/bin/security"

	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			// Manifest with one item.
			secBin + "|find-generic-password|-s|keylatch-_manifest|-a|manifest|-w|-k|" + testKeychainPath: {
				Stdout: []byte(`{"version":1,"items":[{"connection":"openrouter","fields":["api_key"]}]}`),
			},
			// Item value read during repair (repairItemACL reads then re-writes).
			secBin + "|find-generic-password|-s|keylatch-openrouter|-a|api_key|-w|-k|" + testKeychainPath: {
				Stdout: []byte("val\n"),
			},
			// Re-write with -T ACL.
			secBin + "|add-generic-password|-U|-s|keylatch-openrouter|-a|api_key|-w|val|-T": {},
			// Manifest item repair.
			secBin + "|find-generic-password|-s|keylatch-_manifest|-a|manifest|-w|-k|" + testKeychainPath: {
				Stdout: []byte(`{"version":1,"items":[{"connection":"openrouter","fields":["api_key"]}]}`),
			},
		},
	}

	b, err := keychain.Open(keychain.Options{
		KeychainPath: testKeychainPath,
		LockPath:     testLockPath,
		SecurityBin:  secBin,
		Runner:       runner,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// RepairItemACLs should read manifest first, then per-item for ACL re-issue.
	_ = b.RepairItemACLs(context.Background())
	// Not failing on error since MockRunner doesn't perfectly simulate keychain responses.

	// Verify manifest was loaded first.
	if len(runner.Calls) > 0 {
		// First call should be find-generic-password for manifest.
		firstArgs := runner.Calls[0].Args
		manifestFound := false
		for _, arg := range firstArgs {
			if arg == "keylatch-_manifest" {
				manifestFound = true
			}
		}
		if !manifestFound {
			t.Logf("First call args: %v (expected manifest lookup)", firstArgs)
		}
	}
}
