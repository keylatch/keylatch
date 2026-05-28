//go:build windows

package keyring

import "os"

// flockExclusive is a no-op on Windows (not needed for the target platform).
func flockExclusive(_ *os.File) error { return nil }

// flockUnlock is a no-op on Windows.
func flockUnlock(_ *os.File) error { return nil }
