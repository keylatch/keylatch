package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"testing"

	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// setupDaemonPSKey builds the MockRunner response key for
// `ps -p <pid> -o command=` — matches the arg-signature construction used
// by kexec.MockRunner.
func setupDaemonPSKey(psBin string, pid int) string {
	return psBin + "|-p|" + strconv.Itoa(pid) + "|-o|command="
}

// withMockSetupGatewayPS installs a mocked runner/psBin for
// setupStep3SpawnDaemon's process-identity check for the duration of a
// test, restoring the real values afterward.
func withMockSetupGatewayPS(t *testing.T, runner kexec.CommandRunner, psBin string) {
	t.Helper()
	oldRunner, oldBin := setupGatewayPSRunner, setupGatewayPSBin
	t.Cleanup(func() {
		setupGatewayPSRunner, setupGatewayPSBin = oldRunner, oldBin
	})
	setupGatewayPSRunner, setupGatewayPSBin = runner, psBin
}

// TestSetupStep3SpawnDaemon_AlreadyRunning_IdentityConfirmed verifies that
// setup's step 3 checks IsRunning AND process identity (warn-2), and
// presents a confirmed-running gateway as a success (skip), instead of
// shelling out to `gateway up --detach` and reporting the child's expected
// refusal as a setup failure (M1).
func TestSetupStep3SpawnDaemon_AlreadyRunning_IdentityConfirmed(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", configDir)

	pidPath := paths.GatewayPID(llmcontext.DefaultLookup)
	require.NoError(t, os.MkdirAll(paths.GatewayDir(llmcontext.DefaultLookup), 0o700))
	mypid := os.Getpid()
	require.NoError(t, gateway.WritePID(pidPath, mypid))

	withMockSetupGatewayPS(t, &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			setupDaemonPSKey("/bin/ps", mypid): {
				Stdout:   []byte("/usr/local/bin/keylatchd --detach\n"),
				ExitCode: 0,
			},
		},
	}, "/bin/ps")

	var stdout bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&stdout)
	cmd.SetErr(io.Discard)

	setupStep3SpawnDaemon(cmd)

	require.Contains(t, stdout.String(), fmt.Sprintf("Gateway already running (pid %d) — skipping", mypid))
	require.NotContains(t, stdout.String(), "gateway init:")
	require.NotContains(t, stdout.String(), "gateway up:")

	// The confirmed-real gateway's PID file must survive.
	_, stillRunning := gateway.IsRunning(pidPath)
	require.True(t, stillRunning)
}

// TestSetupStep3SpawnDaemon_StaleIdentityInconclusive_SkipsWithNote verifies
// the warn-2/warn-4 fail-safe combination: when process-identity
// verification is inconclusive (ps itself failed), setup must keep the
// current skip behavior — never guess and remove a possibly-live gateway's
// PID file — but must say the check was inconclusive rather than silently
// implying a confirmed match.
func TestSetupStep3SpawnDaemon_StaleIdentityInconclusive_SkipsWithNote(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", configDir)

	pidPath := paths.GatewayPID(llmcontext.DefaultLookup)
	require.NoError(t, os.MkdirAll(paths.GatewayDir(llmcontext.DefaultLookup), 0o700))
	mypid := os.Getpid()
	require.NoError(t, gateway.WritePID(pidPath, mypid))

	withMockSetupGatewayPS(t, &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			setupDaemonPSKey("/bin/ps", mypid): {
				Err: errors.New("exec: ps: not found"),
			},
		},
	}, "/bin/ps")

	var stdout bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&stdout)
	cmd.SetErr(io.Discard)

	setupStep3SpawnDaemon(cmd)

	require.Contains(t, stdout.String(), fmt.Sprintf("Gateway already running (pid %d) — skipping", mypid))
	require.Contains(t, stdout.String(), "could not verify process identity")
	require.NotContains(t, stdout.String(), "gateway init:")
	require.NotContains(t, stdout.String(), "gateway up:")

	// Fail-safe: the PID file must never be removed on inconclusive
	// evidence — the original process could still be alive and healthy.
	_, stillRunning := gateway.IsRunning(pidPath)
	require.True(t, stillRunning)
}

// Note: the "confirmed stale (mismatch) — remove and proceed to actually
// start the gateway" path is exercised end-to-end by
// TestResolveGatewayUpRunning_ForceMismatch_RecoversStalePID in
// gateway_up_force_test.go, which setupStep3SpawnDaemon now delegates to
// directly. It is not re-exercised here: past that branch,
// setupStep3SpawnDaemon unconditionally shells out via os.Executable() to
// run `gateway init`/`gateway up`, which — same as every other test in this
// file that passes --no-daemon-start to avoid calling this function at all
// — would spawn the `go test` binary itself as a subprocess with
// unpredictable behavior, not a safe or meaningful thing to assert on in a
// unit test.
