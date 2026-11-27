//go:build linux

package runner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mxFakeBwrap(t *testing.T, exitCode string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nexit " + exitCode + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bwrap"), []byte(script), 0o755)) //nolint:gosec // fake must be executable
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func mxSandboxReq(cmd ...string) runner.ExecRequest {
	return runner.ExecRequest{
		ConnectionSlug: "testprovider",
		Command:        cmd,
		FeatureFlags:   map[string]bool{"direct_classic_sandboxed": true},
	}
}

func TestClassicSandboxed_FeatureFlagGatesEverything(t *testing.T) {
	em := &mxEmitter{}
	d := runner.NewClassicSandboxedDriver(em)
	req := mxSandboxReq("/bin/sh")
	req.FeatureFlags = nil
	_, err := d.Run(context.Background(), req, sandboxedTmpl("testprovider"))
	assert.ErrorIs(t, err, sandbox.ErrFeatureFlagRequired)
	assert.Empty(t, em.actions(), "nothing may be audited or executed without the flag")

	_, err = d.Run(context.Background(), mxSandboxReq(), sandboxedTmpl("testprovider"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty command")
}

func TestClassicSandboxed_UnhashableExecutableRefused(t *testing.T) {
	em := &mxEmitter{}
	d := runner.NewClassicSandboxedDriver(em)
	_, err := d.Run(context.Background(), mxSandboxReq(filepath.Join(t.TempDir(), "missing-bin")), sandboxedTmpl("testprovider"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hash executable")
	require.Equal(t, []audit.Action{audit.ActionSandboxLaunchRefused}, em.actions())
	em.mu.Lock()
	ev := em.events[0]
	em.mu.Unlock()
	assert.Equal(t, audit.OutcomeDenied, ev.Outcome)
	assert.Equal(t, "hash-compute-failed", ev.Extra["reason"])

	// A nil emitter is tolerated on the same path.
	_, err = runner.NewClassicSandboxedDriver(nil).Run(context.Background(), mxSandboxReq(filepath.Join(t.TempDir(), "missing-bin")), sandboxedTmpl("testprovider"))
	require.Error(t, err)
}

func TestClassicSandboxed_LaunchesThroughBwrap(t *testing.T) {
	mxFakeBwrap(t, "0")
	em := &mxEmitter{}
	rec, err := runner.NewClassicSandboxedDriver(em).Run(context.Background(), mxSandboxReq("/bin/sh"), sandboxedTmpl("testprovider"))
	require.NoError(t, err)
	assert.Equal(t, "direct_classic_sandboxed", rec.Runtime)
	actions := em.actions()
	require.NotEmpty(t, actions)
	assert.Equal(t, audit.ActionSandboxLaunched, actions[0])
	assert.Contains(t, actions, audit.ActionSandboxDenyApplied)
	em.mu.Lock()
	launched := em.events[0]
	em.mu.Unlock()
	assert.Equal(t, "/bin/sh", launched.Extra["executable"])
	assert.Len(t, launched.Extra["executable_sha256"], 64)

	_, err = runner.NewClassicSandboxedDriver(nil).Run(context.Background(), mxSandboxReq("/bin/sh"), sandboxedTmpl("testprovider"))
	require.NoError(t, err)
}

func TestClassicSandboxed_BwrapFailureSurfaces(t *testing.T) {
	mxFakeBwrap(t, "3")
	_, err := runner.NewClassicSandboxedDriver(nil).Run(context.Background(), mxSandboxReq("/bin/sh"), sandboxedTmpl("testprovider"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bwrap exited 3")
}
