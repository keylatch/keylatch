package cli

import "testing"

// AllowInsecureFileKEK makes bootstrap keep the vault key in a plaintext file
// for the rest of the test, as the operator's config file does on a runner with
// no keyring.
func AllowInsecureFileKEK(t *testing.T) {
	t.Helper()
	prev := insecureFileKEKAllowed
	insecureFileKEKAllowed = func() bool { return true }
	t.Cleanup(func() { insecureFileKEKAllowed = prev })
}
