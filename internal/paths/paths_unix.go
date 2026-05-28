//go:build !windows

package paths

import (
	"fmt"
	"os"
	"syscall"
)

// assertOwner checks that the path is owned by the current process uid.
// On Unix systems this is verified via syscall.Stat_t. On Windows (paths_windows.go)
// the check is skipped because ownership semantics differ.
func assertOwner(p string, info os.FileInfo) error {
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// Cannot determine ownership on this platform; skip.
		return nil
	}
	currentUID := uint32(os.Getuid()) //nolint:gosec // G115: os.Getuid() returns a non-negative value bounded by uid_t range on all Unix platforms
	if sys.Uid != currentUID {
		return &UnsafeMode{
			Path: p,
			Got:  info.Mode().Perm(),
			Want: fmt.Sprintf("owned by uid %d (got %d)", currentUID, sys.Uid),
		}
	}
	return nil
}
