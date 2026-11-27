package customsecret

import "time"

// lockWait bounds how long a command waits for the lock; backend calls run under it.
var lockWait = 30 * time.Second

func lockTimeoutError(lockPath string) error {
	return &lockTimeout{path: lockPath}
}

type lockTimeout struct{ path string }

func (e *lockTimeout) Error() string {
	return "another keylatch process has held " + e.path + " for " + lockWait.String() + "; retry, or remove the file if no keylatch process is running"
}
