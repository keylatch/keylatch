//go:build windows

package cli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

const (
	launchTreeHelperEnv  = "KEYLATCH_LAUNCH_TREE_HELPER"
	launchTreePIDFileEnv = "KEYLATCH_LAUNCH_TREE_PID_FILE"
)

// TestLaunchTreeHelper is the harness started by TestLaunchStopsProcessTreeOnExit:
// as "harness" it starts a long-running child, records its pid and exits.
func TestLaunchTreeHelper(t *testing.T) {
	switch os.Getenv(launchTreeHelperEnv) {
	case "harness":
		child := exec.Command(os.Args[0], "-test.run=^TestLaunchTreeHelper$")
		child.Env = append(os.Environ(), launchTreeHelperEnv+"=sleep")
		require.NoError(t, child.Start())
		require.NoError(t, os.WriteFile(os.Getenv(launchTreePIDFileEnv), []byte(strconv.Itoa(child.Process.Pid)), 0o600))
	case "sleep":
		time.Sleep(30 * time.Second)
	default:
		t.Skip("helper process for TestLaunchStopsProcessTreeOnExit")
	}
}

func TestLaunchPreservesChildExitStatus(t *testing.T) {
	err := launchCommandError(superviseLaunch(exec.CommandContext(context.Background(), "cmd", "/c", "exit 23")))
	var cliErr *CLIError
	require.ErrorAs(t, err, &cliErr)
	require.Equal(t, 23, cliErr.Code)
	require.True(t, cliErr.Quiet, "the harness's own exit status needs no message")

	require.NoError(t, launchCommandError(superviseLaunch(exec.CommandContext(context.Background(), "cmd", "/c", "exit 0"))))
}

func TestLaunchStopsProcessTreeOnExit(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "background.pid")
	cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestLaunchTreeHelper$")
	cmd.Env = append(os.Environ(), launchTreeHelperEnv+"=harness", launchTreePIDFileEnv+"="+pidFile)
	require.NoError(t, superviseLaunch(cmd))

	data, err := os.ReadFile(pidFile)
	require.NoError(t, err)
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	require.NoError(t, err)

	proc, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return
	}
	require.NoError(t, err)
	defer func() { _ = windows.CloseHandle(proc) }()
	event, err := windows.WaitForSingleObject(proc, 5000)
	require.NoError(t, err)
	require.Equal(t, uint32(windows.WAIT_OBJECT_0), event, "a process the harness left running must be stopped")
}

func TestLaunchStopsProcessTreeOnCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLaunchTreeHelper$")
	cmd.Env = append(os.Environ(), launchTreeHelperEnv+"=sleep")

	start := time.Now()
	err := launchCommandError(superviseLaunch(cmd))
	require.Less(t, time.Since(start), 10*time.Second, "cancelling launch must stop the harness")
	var cliErr *CLIError
	require.ErrorAs(t, err, &cliErr)
	require.Equal(t, 1, cliErr.Code)
}
