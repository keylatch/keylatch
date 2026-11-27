//go:build windows

package token

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// The lock covers one byte at offset 0. Windows byte-range locks belong to the
// handle and every call opens a fresh one, so the lock serializes goroutines in
// this process as well as other processes, and the OS drops it when a holder
// exits.
const lockedBytes = 1

// lockExclusive opens lockPath and blocks until it holds an exclusive lock on
// it. The returned function releases the lock and closes the file.
func lockExclusive(lockPath string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	h := windows.Handle(f.Fd())
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, lockedBytes, 0, new(windows.Overlapped)); err != nil {
		f.Close() //nolint:errcheck
		return nil, err
	}
	return func() {
		windows.UnlockFileEx(h, 0, lockedBytes, 0, new(windows.Overlapped)) //nolint:errcheck
		f.Close()                                                           //nolint:errcheck
	}, nil
}

// withStoreLock runs fn while holding an exclusive lock on storePath+".lock".
// A lock that cannot be taken is an error: the store is never changed unlocked.
func withStoreLock(storePath string, fn func() error) error {
	if storePath == "" {
		return fn()
	}
	unlock, err := lockExclusive(storePath + ".lock")
	if err != nil {
		return fmt.Errorf("token store lock: %w", err)
	}
	defer unlock()
	return fn()
}
