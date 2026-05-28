//go:build windows

package gateway

import "os"

// Windows PID file crash recovery notes:
//
// Unlike Unix, Windows does not automatically remove PID files when a process
// crashes. If keylatchd exits unexpectedly, the PID file may remain on disk
// with a stale PID.
//
// Windows PID reuse policy: Windows typically waits at least 60 seconds before
// reusing a PID (the "PID reuse delay"), but this is not guaranteed. A stale
// PID file could therefore match a completely different process.
//
// Startup detection: IsRunning uses FindProcess + an OpenProcess probe. If the
// stale PID has been reused by a different process, IsRunning may incorrectly
// return true. In that case, keylatch daemon start will refuse to start.
//
// Recovery: If keylatch reports the daemon is already running but it is not,
// remove the stale PID file with:
//
//	keylatch daemon stop --force
//
// This removes the PID file without sending a signal. You can then start the
// daemon normally.

// isAlive checks liveness via OpenProcess — on Windows, FindProcess calls
// OpenProcess and returns an error if the PID does not exist.
//
// Note: this is a best-effort check. Due to PID reuse, a returned true does
// not guarantee the matching process is a keylatch daemon. See crash recovery
// notes above.
func isAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	proc.Release() //nolint:errcheck
	return true
}

// terminateProcess kills the process — Windows has no SIGTERM equivalent.
func terminateProcess(proc *os.Process) error {
	return proc.Kill()
}
