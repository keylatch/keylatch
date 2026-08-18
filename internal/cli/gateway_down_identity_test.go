package cli

import (
	"context"
	"errors"
	"os"
	"runtime"
	"testing"

	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/stretchr/testify/require"
)

// --- resolveGatewayDownAction (mocked-runner match/mismatch coverage) ---
//
// Mirrors gateway_up_force_test.go's coverage of resolveGatewayUpRunning:
// `gateway down` previously sent SIGTERM to whatever process currently held
// the PID with zero identity verification, unlike `gateway up` which refuses
// to act on unverified/mismatched PIDs. These tests cover the same four
// outcomes for the stop path.

func TestResolveGatewayDownAction_Match_Proceeds(t *testing.T) {
	mypid := os.Getpid()
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			psKey("/bin/ps", mypid): {
				Stdout:   []byte("/usr/local/bin/keylatchd --detach\n"),
				ExitCode: 0,
			},
		},
	}

	action, note := resolveGatewayDownAction(context.Background(), mypid, "/tmp/gateway.pid", false, runner, "/bin/ps")
	require.Equal(t, gatewayDownProceed, action)
	require.Empty(t, note)
}

func TestResolveGatewayDownAction_Mismatch_DoesNotSignal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ps-based identity verification is unavailable on Windows")
	}

	mypid := os.Getpid()
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			psKey("/bin/ps", mypid): {
				Stdout:   []byte("/usr/bin/some-unrelated-process\n"),
				ExitCode: 0,
			},
		},
	}

	action, note := resolveGatewayDownAction(context.Background(), mypid, "/tmp/gateway.pid", false, runner, "/bin/ps")
	require.Equal(t, gatewayDownStalePID, action)
	require.Contains(t, note, "does not look like a keylatch process")
	require.Contains(t, note, "not sending a signal")
}

// TestResolveGatewayDownAction_InconclusiveNoForce_RefusesFailSafe verifies
// the core fix: on inconclusive identity evidence, `gateway down` must
// refuse to signal rather than guess — the previous behavior would have
// sent SIGTERM regardless.
func TestResolveGatewayDownAction_InconclusiveNoForce_RefusesFailSafe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ps-based identity verification is unavailable on Windows")
	}

	mypid := os.Getpid()
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			psKey("/bin/ps", mypid): {
				Err: errors.New("exec: ps: not found"),
			},
		},
	}

	action, note := resolveGatewayDownAction(context.Background(), mypid, "/tmp/gateway.pid", false, runner, "/bin/ps")
	require.Equal(t, gatewayDownRefuse, action)
	require.Contains(t, note, "could not verify process identity")
	require.Contains(t, note, "inconclusive evidence")
	require.Contains(t, note, "/tmp/gateway.pid")
}

func TestResolveGatewayDownAction_InconclusiveWithForce_Proceeds(t *testing.T) {
	mypid := os.Getpid()
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			psKey("/bin/ps", mypid): {
				Err: errors.New("exec: ps: not found"),
			},
		},
	}

	action, note := resolveGatewayDownAction(context.Background(), mypid, "/tmp/gateway.pid", true, runner, "/bin/ps")
	require.Equal(t, gatewayDownProceed, action)
	require.Contains(t, note, "--force was given")
}
