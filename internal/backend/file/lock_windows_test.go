//go:build windows

package file

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsLockFileEx(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".lock")
	open := func() *os.File {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	holder, other := open(), open()

	if err := lockFile(holder); err != nil {
		t.Fatal(err)
	}
	err := windows.LockFileEx(windows.Handle(other.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, lockedBytes, 0, new(windows.Overlapped))
	if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		t.Fatalf("a second handle took the vault lock while it was held: %v", err)
	}
	if err := unlockFile(holder); err != nil {
		t.Fatal(err)
	}
	if err := lockFile(other); err != nil {
		t.Fatalf("the vault lock was not released: %v", err)
	}
	_ = unlockFile(other)
}
