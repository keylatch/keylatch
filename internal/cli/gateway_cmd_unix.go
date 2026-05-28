//go:build !windows

// Package cli — POSIX-specific gateway --detach implementation.
package cli

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// startDetached relaunches the current binary with args in a new session,
// detached from the calling terminal. It returns as soon as the child process
// has been started; the child writes its own PID file atomically on startup.
//
// pidPath is passed so that the caller can poll for the file after this
// function returns (see the polling loop in newGatewayUpCmd).
func startDetached(args []string, pidPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("gateway up: resolve executable: %w", err)
	}
	cmd := exec.Command(exe, args...) //nolint:gosec // argv is constructed from validated flag values
	cmd.Env = os.Environ()
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("gateway up: start background process: %w", err)
	}
	// The child writes its own PID file atomically on startup.
	// The caller's poll loop (newGatewayUpCmd) waits up to 3 s for it.
	_ = pidPath
	return nil
}
