//go:build harness && !windows

package harness

import (
	"os/exec"
	"syscall"
)

// ownGroup starts cmd in its own process group, so ending a call also ends
// whatever a command the hooks let through left running in the background
// instead of orphaning it.
func ownGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return killGroup(cmd) }
}

func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
