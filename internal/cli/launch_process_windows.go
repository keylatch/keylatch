//go:build windows

package cli

import (
	"errors"
	"os"
	"os/exec"
)

// configureLaunchProcess kills the harness when launch is interrupted.
// Windows has no process groups to hand the console to; processes the
// harness starts itself are not stopped with it.
func configureLaunchProcess(cmd *exec.Cmd) {
	cmd.Cancel = func() error { return stopLaunchProcess(cmd) }
}

func stopLaunchProcess(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	err := cmd.Process.Kill()
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}

func restoreLaunchTerminal(*exec.Cmd) error { return nil }

func launchExitCode(err *exec.ExitError) int {
	if code := err.ExitCode(); code >= 0 {
		return code
	}
	return 1
}
