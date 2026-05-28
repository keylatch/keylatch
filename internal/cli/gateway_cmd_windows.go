//go:build windows

// Package cli — Windows-specific gateway --detach implementation.
package cli

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// startDetached relaunches the current binary with args as an independent
// Windows background process (new process group, detached console, hidden
// window). It returns as soon as the child process has been started; the
// child is responsible for writing its own PID file on startup.
//
// pidPath is passed so that the caller can poll for the file after this
// function returns (see the polling loop in newGatewayUpCmd).
//
// Creation flags used:
//   - CREATE_NEW_PROCESS_GROUP (0x00000200): new process group, so
//     Ctrl+C/Ctrl+Break signals sent to the parent are not forwarded.
//   - DETACHED_PROCESS (0x00000008): detaches the child from the parent's
//     console entirely, preventing CTRL_CLOSE_EVENT from killing it when
//     the terminal window closes.
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
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS
		// syscall.DETACHED_PROCESS is not exported in the Go stdlib syscall
		// package; use the Win32 literal 0x00000008 directly.
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008,
		HideWindow:    true,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("gateway up: start background process: %w", err)
	}
	// The child writes its own PID file atomically on startup.
	// The caller's poll loop (newGatewayUpCmd) waits up to 3 s for it.
	_ = pidPath
	return nil
}
