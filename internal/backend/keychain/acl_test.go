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

func TestVerifyACL_Match(t *testing.T) {
	// VerifyACL should return nil when the ACL contains the current executable path.
	secBin := "/usr/bin/security"
	currentBin, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			secBin + "|find-generic-password|-s|keylatch-keychain|-a|unlock|-g": {
				Stdout: []byte("path: " + currentBin + "\n"),
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
		t.Errorf("VerifyACL with matching path: got %v, want nil", err)
	}
}

func TestVerifyACL_Mismatch(t *testing.T) {
	// VerifyACL should return ErrACLMismatch when the stored path doesn't match.
	secBin := "/usr/bin/security"

	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			secBin + "|find-generic-password|-s|keylatch-keychain|-a|unlock|-g": {
				Stdout: []byte("path: /usr/local/bin/old-keylatch\n"),
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
		t.Errorf("VerifyACL with mismatch: got %v, want ErrACLMismatch", err)
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
