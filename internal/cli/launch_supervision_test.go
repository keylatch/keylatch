//go:build !windows

package cli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLaunchPreservesChildExitStatus(t *testing.T) {
	err := launchCommandError(superviseLaunch(exec.CommandContext(context.Background(), "sh", "-c", "exit 23")))
	var cliErr *CLIError
	require.ErrorAs(t, err, &cliErr)
	require.Equal(t, 23, cliErr.Code)
	require.True(t, cliErr.Quiet, "the harness's own exit status needs no message")

	require.NoError(t, launchCommandError(superviseLaunch(exec.CommandContext(context.Background(), "true"))))
}

func TestLaunchStopsProcessGroupOnExit(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "background.pid")
	cmd := exec.CommandContext(context.Background(), "sh", "-c", `sleep 30 & echo $! > "$1"`, "harness", pidFile)
	require.NoError(t, superviseLaunch(cmd))

	data, err := os.ReadFile(pidFile)
	require.NoError(t, err)
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			return true
		}
		// An exited process may linger as a zombie until init reaps it.
		stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		return err == nil && strings.Contains(string(stat), ") Z ")
	}, 3*time.Second, 10*time.Millisecond, "a process the harness left running must be stopped")
}

func TestLaunchReportsMissingCommand(t *testing.T) {
	err := launchCommandError(superviseLaunch(exec.CommandContext(context.Background(), filepath.Join(t.TempDir(), "missing-command"))))
	var cliErr *CLIError
	require.ErrorAs(t, err, &cliErr)
	require.False(t, cliErr.Quiet)
	require.Contains(t, err.Error(), "start agent")
}
