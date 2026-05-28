//go:build windows

package paths

import "os"

// assertOwner is a no-op on Windows. Windows uses ACLs rather than Unix-style
// uid ownership, so this check is not applicable.
func assertOwner(_ string, _ os.FileInfo) error {
	return nil
}
