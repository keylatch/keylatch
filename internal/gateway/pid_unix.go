//go:build !windows

package gateway

import (
	"os"
	"syscall"
)

// isAlive probes the process using signal 0 — Unix-only.
func isAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

// terminateProcess sends SIGTERM.
func terminateProcess(proc *os.Process) error {
	return proc.Signal(syscall.SIGTERM)
}
