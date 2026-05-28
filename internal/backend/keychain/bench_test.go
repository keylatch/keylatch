//go:build darwin

package keychain_test

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/backend/keychain"
	kexec "github.com/keylatch/keylatch/internal/exec"
)

// BenchmarkKeychainGet benchmarks a full unlock-read-lock cycle via MockRunner.
// Target: < 100ms p99 per run (excluding real keychain I/O).
func BenchmarkKeychainGet(b *testing.B) {
	secBin := "/usr/bin/security"
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			secBin + "|find-generic-password|-s|keylatch-keychain|-a|unlock|-w": {
				Stdout: []byte("bench-unlock-password\n"),
			},
			secBin + "|unlock-keychain|-p|bench-unlock-password|" + testKeychainPath: {},
			secBin + "|lock-keychain|" + testKeychainPath:                            {},
			secBin + "|find-generic-password|-s|keylatch-_manifest|-a|manifest|-w|-k|" + testKeychainPath: {
				Stdout: []byte(`{"version":1,"items":[{"connection":"benchconn","fields":["api_key"]}]}`),
			},
			secBin + "|find-generic-password|-s|keylatch-benchconn|-a|api_key|-w|-k|" + testKeychainPath: {
				Stdout: []byte("bench-secret-value\n"),
			},
		},
	}

	be, err := keychain.Open(keychain.Options{
		KeychainPath: testKeychainPath,
		LockPath:     testLockPath,
		SecurityBin:  secBin,
		Runner:       runner,
	})
	if err != nil {
		b.Fatalf("keychain.Open: %v", err)
	}

	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runner.Reset()
		_, _, _ = be.Get(ctx, "default/benchconn/api_key")
	}
}
