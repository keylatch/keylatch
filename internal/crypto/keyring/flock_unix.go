//go:build darwin || linux || freebsd

package keyring

import (
	"os"
	"syscall"
)

// flockExclusive acquires an exclusive flock on f (blocking).
func flockExclusive(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

// flockUnlock releases the flock on f.
func flockUnlock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
