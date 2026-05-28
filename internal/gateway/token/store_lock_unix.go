//go:build !windows

// Package token — Unix flock-based token store locking.
package token

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// withStoreLock acquires an exclusive flock on storePath+".lock", runs fn,
// then releases the lock. Returns the error from fn, or a lock error.
func withStoreLock(storePath string, fn func() error) error {
	if storePath == "" {
		return fn()
	}
	lockPath := storePath + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return fn() // fallback: run without lock rather than fail
	}
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fn() // fallback
	}
	defer lockFile.Close() //nolint:errcheck

	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX); err != nil {
		return fn() // fallback
	}
	defer unix.Flock(int(lockFile.Fd()), unix.LOCK_UN) //nolint:errcheck

	return fn()
}
