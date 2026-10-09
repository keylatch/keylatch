//go:build windows

package keyring

import (
	"os"

	"golang.org/x/sys/windows"
)

// The lock covers one byte at offset 0. Windows byte-range locks belong to the
// handle, and acquireFlock opens a fresh handle per call, so the lock
// serializes handles in the same process as well as separate processes.
const lockedBytes = 1

// flockExclusive blocks until it holds an exclusive lock on f.
func flockExclusive(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, lockedBytes, 0, new(windows.Overlapped))
}

// flockUnlock releases the lock taken by flockExclusive.
func flockUnlock(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, lockedBytes, 0, new(windows.Overlapped))
}
