package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/stretchr/testify/require"
)

// --- L2: resolveGatewayUpRunning (mocked-runner match/mismatch coverage) ---

// psKey builds the MockRunner response key for `ps -p <pid> -o command=`,
// matching the arg-signature construction used by kexec.MockRunner.
func psKey(psBin string, pid int) string {
	return psBin + "|-p|" + strconv.Itoa(pid) + "|-o|command="
}

func TestResolveGatewayUpRunning_NotRunning(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "gateway.pid")

	action, pid, note := resolveGatewayUpRunning(context.Background(), pidPath, false, &kexec.MockRunner{}, "/bin/ps")
	require.Equal(t, gatewayUpProceed, action)
	require.Zero(t, pid)
	require.Empty(t, note)
}

func TestResolveGatewayUpRunning_RunningNoForce(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "gateway.pid")
	require.NoError(t, gateway.WritePID(pidPath, os.Getpid()))

	action, pid, note := resolveGatewayUpRunning(context.Background(), pidPath, false, &kexec.MockRunner{}, "/bin/ps")
	require.Equal(t, gatewayUpRefuse, action)
	require.Equal(t, os.Getpid(), pid)
	require.Empty(t, note, "no --force means no identity verification attempted")

	// PID file must be untouched — refusal without --force never removes it.
	_, stillRunning := gateway.IsRunning(pidPath)
	require.True(t, stillRunning)
}

func TestResolveGatewayUpRunning_ForceMatch_Refuses(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "gateway.pid")
	mypid := os.Getpid()
	require.NoError(t, gateway.WritePID(pidPath, mypid))

	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			psKey("/bin/ps", mypid): {
				Stdout:   []byte("/usr/local/bin/keylatchd --detach\n"),
				ExitCode: 0,
			},
		},
	}

	action, pid, note := resolveGatewayUpRunning(context.Background(), pidPath, true, runner, "/bin/ps")
	require.Equal(t, gatewayUpRefuse, action)
	require.Equal(t, mypid, pid)
	require.Contains(t, note, "identity verification confirmed")

	// A confirmed-real gateway's PID file must survive.
	_, stillRunning := gateway.IsRunning(pidPath)
	require.True(t, stillRunning)
}

func TestResolveGatewayUpRunning_ForceMismatch_RecoversStalePID(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "gateway.pid")
	mypid := os.Getpid()
	require.NoError(t, gateway.WritePID(pidPath, mypid))

	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			psKey("/bin/ps", mypid): {
				Stdout:   []byte("/usr/bin/some-unrelated-process\n"),
				ExitCode: 0,
			},
		},
	}

	action, pid, note := resolveGatewayUpRunning(context.Background(), pidPath, true, runner, "/bin/ps")
	require.Equal(t, gatewayUpProceed, action)
	require.Equal(t, mypid, pid)
	require.Contains(t, note, "stale PID file recovered")

	// The stale PID file must have been removed so a fresh gateway can start.
	_, err := os.Stat(pidPath)
	require.True(t, os.IsNotExist(err), "stale PID file should have been removed")
}

// TestResolveGatewayUpRunning_ForceUnchecked_RefusesFailSafe verifies the
// review fix (warn-4): when process-identity verification is inconclusive
// (ps itself failed — could mean the original process legitimately died, or
// could mean ps failed while the process is still alive and healthy),
// resolveGatewayUpRunning must fail safe and refuse rather than guess by
// removing the PID file and starting a second gateway alongside a possibly
// live one.
func TestResolveGatewayUpRunning_ForceUnchecked_RefusesFailSafe(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "gateway.pid")
	mypid := os.Getpid()
	require.NoError(t, gateway.WritePID(pidPath, mypid))

	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			psKey("/bin/ps", mypid): {
				Err: errors.New("exec: ps: not found"),
			},
		},
	}

	action, pid, note := resolveGatewayUpRunning(context.Background(), pidPath, true, runner, "/bin/ps")
	require.Equal(t, gatewayUpRefuse, action)
	require.Equal(t, mypid, pid)
	require.Contains(t, note, "could not verify process identity")
	require.Contains(t, note, "inconclusive evidence")

	// The PID file must survive untouched — never remove it on
	// inconclusive evidence, since the original process may still be alive.
	_, stillRunning := gateway.IsRunning(pidPath)
	require.True(t, stillRunning, "PID file must not be removed when identity verification is inconclusive")
}
