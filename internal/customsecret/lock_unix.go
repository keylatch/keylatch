//go:build linux || darwin || freebsd || netbsd || openbsd

package customsecret

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// lockWait bounds how long a command waits for the lock; backend calls run under it.
var lockWait = 30 * time.Second

// lockFile takes an advisory exclusive lock on a sidecar of the rules file,
// so concurrent keylatch processes do not lose each other's changes.
func lockFile(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(lockWait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EINTR {
			_ = f.Close()
			return nil, err
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("another keylatch process has held %s for %s; retry, or remove the file if no keylatch process is running", path+".lock", lockWait)
		}
		time.Sleep(25 * time.Millisecond)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
