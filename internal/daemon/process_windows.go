//go:build windows

package daemon

import "os/exec"

func detachCommand(_ *exec.Cmd) {}
