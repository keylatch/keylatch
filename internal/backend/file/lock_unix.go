//go:build unix

package file

import (
	"os"
	"syscall"
)

// lockFile blocks until it holds an exclusive advisory lock on f.
func lockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }

// unlockFile releases the lock taken by lockFile.
func unlockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
