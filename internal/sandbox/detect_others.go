//go:build !linux

package sandbox

// BwrapInstallHint is empty on non-Linux platforms. bwrap is Linux-only.
const BwrapInstallHint = ""

// DetectBwrap is a no-op on non-Linux platforms. bwrap is Linux-only;
// macOS uses sandbox-exec, Windows is unsupported.
// Returns ("", false) always.
func DetectBwrap() (path string, ok bool) {
	return "", false
}
