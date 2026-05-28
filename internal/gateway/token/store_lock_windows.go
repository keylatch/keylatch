//go:build windows

// Package token — Windows best-effort token store locking.
package token

import (
	"os"
	"path/filepath"
	"time"
)

// withStoreLock acquires a best-effort exclusive lock on storePath+".lock" via
// O_CREATE|O_EXCL retry loop (Windows has no flock). Runs fn under the lock.
func withStoreLock(storePath string, fn func() error) error {
	if storePath == "" {
		return fn()
	}
	lockPath := storePath + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return fn() // fallback
	}

	var lockFile *os.File
	var err error
	for i := 0; i < 50; i++ {
		lockFile, err = os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		return fn() // fallback: run without lock
	}
	defer func() {
		lockFile.Close()    //nolint:errcheck
		os.Remove(lockPath) //nolint:errcheck
	}()

	return fn()
}
