//go:build darwin

package keychain

import (
	"fmt"
	"os"
	"syscall"
)

// acquireFlock opens the lock file and acquires an exclusive flock.
// Returns a release function that MUST be deferred by the caller.
// S1-2: serializes all keychain operations across processes.
func acquireFlock(lockPath string) (release func(), err error) {
	// Create the lock file if it doesn't exist.
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("flock: open lock file %q: %w", lockPath, err)
	}

	// Acquire exclusive lock (blocking).
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close() // best-effort cleanup in error path
		return nil, fmt.Errorf("flock: acquire LOCK_EX on %q: %w", lockPath, err)
	}

	release = func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}

	return release, nil
}
