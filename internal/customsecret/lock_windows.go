//go:build windows

package customsecret

import (
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

// The lock covers one byte at offset 0. Windows byte-range locks belong to the
// handle and every call opens a fresh one, so the lock serializes goroutines in
// this process as well as other processes, and the OS drops it when a holder exits.
const lockedBytes = 1

// lockFile takes an exclusive byte-range lock on a sidecar of the rules file.
// A lock that cannot be taken is an error: the rules are never changed unlocked.
func lockFile(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	h := windows.Handle(f.Fd())
	deadline := time.Now().Add(lockWait)
	for {
		err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, lockedBytes, 0, new(windows.Overlapped))
		if err == nil {
			break
		}
		if err != windows.ERROR_LOCK_VIOLATION {
			_ = f.Close()
			return nil, err
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, lockTimeoutError(path + ".lock")
		}
		time.Sleep(25 * time.Millisecond)
	}
	return func() {
		_ = windows.UnlockFileEx(h, 0, lockedBytes, 0, new(windows.Overlapped))
		_ = f.Close()
	}, nil
}
