//go:build !windows

package keyring

import (
	"fmt"
	"os"
)

// enforcePrivateFileMode reports whether the OS lets a test create a keyring
// file whose permissions are wrong, so the permission check can be exercised.
const enforcePrivateFileMode = true

// checkPrivateFile requires the keyring file to be readable and writable by its
// owner only.
func checkPrivateFile(_ string, info os.FileInfo) error {
	if perm := info.Mode().Perm(); perm != 0o600 {
		return fmt.Errorf("has mode %04o, want 0600", perm)
	}
	return nil
}
