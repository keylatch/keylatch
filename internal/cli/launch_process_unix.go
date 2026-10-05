//go:build !windows

package cli

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// startLaunchProcess starts the harness in its own process group and, when
// launch runs on a terminal, makes that group the terminal's foreground. The
// returned function stops the whole group.
func startLaunchProcess(cmd *exec.Cmd) (func() error, error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if cmd.Stdin == os.Stdin && term.IsTerminal(int(os.Stdin.Fd())) {
		cmd.SysProcAttr.Foreground = true
		cmd.SysProcAttr.Ctty = int(os.Stdin.Fd())
	}
	stop := func() error { return stopLaunchProcess(cmd) }
	cmd.Cancel = stop
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return stop, nil
}

func stopLaunchProcess(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

// restoreLaunchTerminal takes the terminal back for launch's own process
// group. launch is a background process at this point, so SIGTTOU is ignored
// while it does.
func restoreLaunchTerminal(cmd *exec.Cmd) error {
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Foreground {
		return nil
	}
	signal.Ignore(syscall.SIGTTOU)
	defer signal.Reset(syscall.SIGTTOU)
	return unix.IoctlSetPointerInt(int(os.Stdin.Fd()), unix.TIOCSPGRP, syscall.Getpgrp())
}

func launchExitCode(err *exec.ExitError) int {
	if code := err.ExitCode(); code >= 0 {
		return code
	}
	if status, ok := err.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return 1
}
