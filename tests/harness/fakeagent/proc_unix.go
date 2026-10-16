//go:build harness && !windows

package main

import (
	"os/exec"
	"syscall"
)

// ownGroup starts cmd in its own process group so a timeout kills everything
// the script started, not only bash: a let-through `find / -exec env \;` or
// `while true; do env; done` otherwise outlives the call and keeps running.
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
