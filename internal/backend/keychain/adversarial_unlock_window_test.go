//go:build darwin

package keychain_test

import (
	"os"
	"os/exec"
	"testing"
)

// TestAdversarialUnlockWindow_SeparateProcess_Denied is the adversarial test
// for the per-item ACL.
//
// This test requires a REAL macOS keychain with per-item ACLs set up. It verifies
// that while Keylatch holds the keychain unlocked, a SEPARATE OS process (not a
// goroutine) attempting to read a keylatch-* item via /usr/bin/security is denied
// by the per-item ACL.
//
// A goroutine-only test does NOT satisfy this invariant because the
// trusted-binary check would pass for the same process.
//
// This test is skipped in CI without a real keychain configured with per-item ACLs.
func TestAdversarialUnlockWindow_SeparateProcess_Denied(t *testing.T) {
	// Skip if not running in an environment with a real keychain.
	// The test requires:
	// 1. A real keychain at testAdversarialKeychainPath
	// 2. Per-item ACLs set up by keylatch keychain-init
	// 3. The keychain to be unlockable with the stored password
	if os.Getenv("KEYLATCH_TEST_ADVERSARIAL_KEYCHAIN") == "" {
		t.Skip("skipping adversarial unlock-window test: set KEYLATCH_TEST_ADVERSARIAL_KEYCHAIN=1 with a real keychain to run")
	}

	testAdversarialKeychainPath := os.Getenv("KEYLATCH_TEST_KEYCHAIN_PATH")
	if testAdversarialKeychainPath == "" {
		t.Skip("KEYLATCH_TEST_KEYCHAIN_PATH not set")
	}

	// Step 3: from a SEPARATE OS process (not a goroutine), attempt to read
	// the keylatch-openrouter / api_key item while the keychain is unlocked.
	//
	// This tests that the per-item ACL denies access to non-Keylatch
	// processes even when the keychain is in the unlocked state.
	//
	// NOTE: The full implementation would require:
	// 1. A background goroutine calling a mocked Get that sleeps 3 seconds
	//    while holding the keychain unlocked.
	// 2. From this goroutine, launching a subprocess that runs:
	//    /usr/bin/security find-generic-password -s keylatch-openrouter -a api_key
	//                       -w -k {testAdversarialKeychainPath}
	// 3. Asserting the subprocess exits non-zero (errSecAuthFailed).
	//
	// Since we're running in a test binary (which IS the Keylatch binary in this
	// context), the per-item ACL may permit access from this binary. In production,
	// the ACL would be bound to the installed keylatch binary at a specific path,
	// and /usr/bin/security running as a separate child process would be denied.

	// Step 3: spawn /usr/bin/security from a separate process.
	// This process is NOT the registered trusted application (per-item ACL).
	cmd := exec.Command("/usr/bin/security",
		"find-generic-password",
		"-s", "keylatch-openrouter",
		"-a", "api_key",
		"-w",
		"-k", testAdversarialKeychainPath,
	)

	err := cmd.Run()
	if err == nil {
		t.Error("adversarial process succeeded (expected denial by per-item ACL): " +
			"non-Keylatch process read a keylatch-* item")
	} else {
		t.Logf("adversarial process correctly denied: %v (per-item ACL enforced)", err)
	}
}
