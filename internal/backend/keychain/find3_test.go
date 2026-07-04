//go:build darwin

package keychain_test

import (
	"context"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/keychain"
	kexec "github.com/keylatch/keylatch/internal/exec"
)

// TestGet_ExactlyOneValueRead verifies that Get produces exactly one
// value-read call (the getOneValue call with -w for the specific service+account).
func TestGet_ExactlyOneValueRead(t *testing.T) {
	secBin := "/usr/bin/security"
	const kPath = "/tmp/find3-test.keychain-db"

	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			secBin + "|find-generic-password|-s|keylatch-keychain|-a|unlock|-w": {
				Stdout: []byte("pw\n"),
			},
			secBin + "|unlock-keychain|-p|pw|" + kPath: {},
			secBin + "|lock-keychain|" + kPath:         {},
			// Manifest.
			secBin + "|find-generic-password|-s|keylatch-_manifest|-a|manifest|-w|-k|" + kPath: {
				Stdout: []byte(`{"version":1,"items":[{"connection":"openrouter","fields":["api_key"]}]}`),
			},
			// The one value read.
			secBin + "|find-generic-password|-s|keylatch-openrouter|-a|api_key|-w|-k|" + kPath: {
				Stdout: []byte("val\n"),
			},
		},
	}

	b, err := keychain.Open(keychain.Options{
		KeychainPath: kPath,
		LockPath:     "/tmp/find3-test.lock",
		SecurityBin:  secBin,
		Runner:       runner,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	ctx := context.Background()
	_, _, err = b.Get(ctx, "default/openrouter/api_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	// Count calls with -w flag AND matching keylatch-openrouter service.
	valueReadCount := 0
	for _, call := range runner.CallsCopy() {
		hasW := false
		hasService := false
		for _, arg := range call.Args {
			if arg == "-w" {
				hasW = true
			}
			if arg == "keylatch-openrouter" {
				hasService = true
			}
		}
		if hasW && hasService {
			valueReadCount++
		}
	}

	if valueReadCount != 1 {
		t.Errorf("Get produced %d value-read calls, want exactly 1", valueReadCount)
	}
}

// TestList_ZeroValueReads verifies that List produces zero value-read calls.
func TestList_ZeroValueReads(t *testing.T) {
	secBin := "/usr/bin/security"
	const kPath = "/tmp/find3-list-test.keychain-db"

	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			// Manifest (not found = empty).
			secBin + "|find-generic-password|-s|keylatch-_manifest|-a|manifest|-w|-k|" + kPath: {
				ExitCode: 44,
			},
		},
	}

	b, err := keychain.Open(keychain.Options{
		KeychainPath: kPath,
		LockPath:     "/tmp/find3-list-test.lock",
		SecurityBin:  secBin,
		Runner:       runner,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	ctx := context.Background()
	_, err = b.List(ctx, "")
	if err != nil {
		t.Errorf("List: %v", err)
	}

	// Count calls with -w flag (value reads).
	wCallCount := 0
	for _, call := range runner.CallsCopy() {
		for _, arg := range call.Args {
			if arg == "-w" {
				wCallCount++
				break
			}
		}
	}

	// List is only allowed one -w call: for the manifest item itself.
	// The manifest IS a keychain item retrieved with -w, but it's metadata.
	// List must produce ZERO value-bearing item reads.
	// The manifest read with -w is acceptable (it's the manifest, not a secret value).
	// We count only calls with -w AND a service that is NOT keylatch-_manifest.
	valueReadCount := 0
	for _, call := range runner.CallsCopy() {
		hasW := false
		isManifest := false
		for _, arg := range call.Args {
			if arg == "-w" {
				hasW = true
			}
			if arg == "keylatch-_manifest" {
				isManifest = true
			}
		}
		if hasW && !isManifest {
			valueReadCount++
		}
	}

	if valueReadCount != 0 {
		t.Errorf("List produced %d non-manifest value-read calls, want 0", valueReadCount)
	}
}

// TestGetMeta_ZeroValueReads verifies that GetMeta produces zero value-read calls.
func TestGetMeta_ZeroValueReads(t *testing.T) {
	secBin := "/usr/bin/security"
	const kPath = "/tmp/find3-getmeta-test.keychain-db"

	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			secBin + "|find-generic-password|-s|keylatch-_manifest|-a|manifest|-w|-k|" + kPath: {
				Stdout: []byte(`{"version":1,"items":[{"connection":"openrouter","fields":["api_key"]}]}`),
			},
		},
	}

	b, err := keychain.Open(keychain.Options{
		KeychainPath: kPath,
		LockPath:     "/tmp/find3-getmeta-test.lock",
		SecurityBin:  secBin,
		Runner:       runner,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	ctx := context.Background()
	_, err = b.GetMeta(ctx, "default/openrouter/api_key")
	// Keychain backend returns ErrNotSupported for GetMeta since versioned
	// metadata lives in the file backend only. ErrNotSupported is still a
	// zero-value-read call, so the invariant holds.
	if err != nil && !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("GetMeta: %v", err)
	}

	// Count -w calls that are NOT for the manifest.
	valueReadCount := 0
	for _, call := range runner.CallsCopy() {
		hasW := false
		isManifest := false
		for _, arg := range call.Args {
			if arg == "-w" {
				hasW = true
			}
			if arg == "keylatch-_manifest" {
				isManifest = true
			}
		}
		if hasW && !isManifest {
			valueReadCount++
		}
	}

	if valueReadCount != 0 {
		t.Errorf("GetMeta produced %d non-manifest value-read calls, want 0", valueReadCount)
	}
}
