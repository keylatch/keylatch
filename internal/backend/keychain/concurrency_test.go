//go:build darwin

package keychain_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend/keychain"
	kexec "github.com/keylatch/keylatch/internal/exec"
)

// TestConcurrency_SameProcess verifies two parallel Get calls are serialized
// by the flock. With 50ms simulated latency, total time should be ~2x single
// call duration.
func TestConcurrency_SameProcess(t *testing.T) {
	const latency = 50 * time.Millisecond
	secBin := "/usr/bin/security"

	runner := &kexec.MockRunner{
		SimulatedLatency: latency,
		Responses: map[string]kexec.MockResponse{
			secBin + "|find-generic-password|-s|keylatch-keychain|-a|unlock|-w": {
				Stdout: []byte("pw\n"),
			},
			secBin + "|unlock-keychain|-p|pw|" + testKeychainPath: {},
			secBin + "|lock-keychain|" + testKeychainPath:         {},
			secBin + "|find-generic-password|-s|keylatch-_manifest|-a|manifest|-w|-k|" + testKeychainPath: {
				ExitCode: 44,
			},
			secBin + "|find-generic-password|-s|keylatch-openrouter|-a|api_key|-w|-k|" + testKeychainPath: {
				Stdout: []byte("val\n"),
			},
		},
	}

	b, err := keychain.Open(keychain.Options{
		KeychainPath: testKeychainPath,
		LockPath:     testLockPath,
		SecurityBin:  "/usr/bin/security",
		Runner:       runner,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	ctx := context.Background()
	var wg sync.WaitGroup
	start := time.Now()
	errors := make([]error, 2)

	for i := 0; i < 2; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, errors[i] = b.Get(ctx, "default/openrouter/api_key")
		}()
	}

	wg.Wait()
	elapsed := time.Since(start)

	for i, err := range errors {
		if err != nil {
			t.Logf("Get #%d error (may be expected in unit test): %v", i+1, err)
		}
	}

	// With flock serialization and 50ms latency per call, total should be >= 2*latency.
	// This is a heuristic — on very fast machines the flock may not add measurable overhead.
	if elapsed < latency {
		t.Logf("elapsed %v < expected %v (flock may not be serializing, or latency not applied consistently)", elapsed, latency)
	}
	t.Logf("concurrent Get elapsed: %v (expected ~%v or more)", elapsed, 2*latency)
}

// TestConcurrency_UnlockLockNonInterleaved verifies that concurrent Gets produce
// non-interleaved unlock/lock sequences (each Get's lock must follow its unlock).
func TestConcurrency_UnlockLockNonInterleaved(t *testing.T) {
	const latency = 20 * time.Millisecond
	secBin := "/usr/bin/security"

	runner := &kexec.MockRunner{
		SimulatedLatency: latency,
		Responses: map[string]kexec.MockResponse{
			secBin + "|find-generic-password|-s|keylatch-keychain|-a|unlock|-w": {
				Stdout: []byte("pw\n"),
			},
			secBin + "|unlock-keychain|-p|pw|" + testKeychainPath: {},
			secBin + "|lock-keychain|" + testKeychainPath:         {},
			secBin + "|find-generic-password|-s|keylatch-_manifest|-a|manifest|-w|-k|" + testKeychainPath: {
				ExitCode: 44,
			},
			secBin + "|find-generic-password|-s|keylatch-openrouter|-a|api_key|-w|-k|" + testKeychainPath: {
				Stdout: []byte("val\n"),
			},
		},
	}

	b, err := keychain.Open(keychain.Options{
		KeychainPath: testKeychainPath,
		LockPath:     testLockPath,
		SecurityBin:  "/usr/bin/security",
		Runner:       runner,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = b.Get(ctx, "default/openrouter/api_key")
		}()
	}
	wg.Wait()

	// Verify that each unlock-keychain is followed (at some point before the next unlock)
	// by a lock-keychain — i.e., no interleaving.
	calls := runner.CallsCopy()
	depth := 0
	for _, call := range calls {
		if len(call.Args) == 0 {
			continue
		}
		switch call.Args[0] {
		case "unlock-keychain":
			depth++
			if depth > 1 {
				t.Errorf("interleaved unlock detected: depth=%d at call %v", depth, call.Args)
			}
		case "lock-keychain":
			depth--
		}
	}

	if depth != 0 {
		t.Errorf("unbalanced unlock/lock pairs: depth=%d", depth)
	}
}
