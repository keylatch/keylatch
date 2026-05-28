//go:build linux

package sandbox

import (
	"fmt"
	"os/exec"
)

// BwrapInstallHint is an actionable install hint shown when bwrap is missing.
const BwrapInstallHint = `bwrap (bubblewrap) is required for direct_classic_sandboxed mode on Linux.

Install it with your package manager:
  apt-get install bubblewrap       # Debian/Ubuntu
  dnf install bubblewrap           # Fedora/RHEL
  pacman -S bubblewrap             # Arch Linux
  nix-env -iA nixpkgs.bubblewrap  # Nix`

// DetectBwrap reports whether bwrap is available on the PATH or at known
// system locations. Returns the resolved path and ok=true when found.
func DetectBwrap() (path string, ok bool) {
	// First try PATH lookup.
	if p, err := exec.LookPath("bwrap"); err == nil {
		return p, true
	}

	// Fallback: check well-known install locations.
	for _, candidate := range []string{"/usr/bin/bwrap", "/usr/local/bin/bwrap"} {
		if p, err := exec.LookPath(candidate); err == nil {
			return p, true
		}
	}

	return "", false
}

// ErrBwrapMissing is returned by RunSandboxed when bwrap is not found.
var ErrBwrapMissing = fmt.Errorf("sandbox: bwrap not found.\n" + BwrapInstallHint)
