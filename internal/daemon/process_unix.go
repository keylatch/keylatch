//go:build !windows

package daemon

import (
	"os/exec"
	"syscall"
)

func detachCommand(cmd *exec.Cmd) {
	// Setsid prevents SIGINT (Ctrl-C) from propagating to the daemon.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
