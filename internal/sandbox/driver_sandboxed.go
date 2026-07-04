// Package sandbox implements the direct_classic_sandboxed runtime driver.
// RunSandboxed is provided by platform-specific files:
// - driver_linux.go (build tag: linux) — uses bwrap
// - driver_darwin.go (build tag: darwin) — uses sandbox-exec
//
// On unsupported platforms a stub returns ErrUnsupportedPlatform.
package sandbox

// indexOf returns the index of the first occurrence of c in s, or -1.
func indexOf(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
