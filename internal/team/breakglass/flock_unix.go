//go:build !windows

package breakglass

import (
	"fmt"
	"os"
	"syscall"
)

// flockAcquire acquires an exclusive advisory lock on f.
func flockAcquire(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("breakglass: acquire lock: %w", err)
	}
	return nil
}

// flockRelease releases the advisory lock on f.
func flockRelease(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
