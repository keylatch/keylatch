//go:build windows

package file

import (
	"os"

	"golang.org/x/sys/windows"
)

// The lock covers one byte at offset 0 of the lock file. Windows byte-range
// locks belong to the handle, and every caller opens its own handle, so the
// lock serializes handles in one process as well as separate processes.
const lockedBytes = 1

// lockFile blocks until it holds an exclusive lock on f.
func lockFile(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, lockedBytes, 0, new(windows.Overlapped))
}

// unlockFile releases the lock taken by lockFile.
func unlockFile(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, lockedBytes, 0, new(windows.Overlapped))
}
