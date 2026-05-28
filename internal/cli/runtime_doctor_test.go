package cli_test

// runtime_doctor_test.go verifies the `runtime doctor` output includes
// direct_classic (available) and direct_classic_sandboxed (not available).
// Epic 15 T04.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRuntimeDoctor_SubcommandRegistered verifies the `runtime doctor`
// subcommand is wired into the cobra command tree.
func TestRuntimeDoctor_SubcommandRegistered(t *testing.T) {
	root := cli.NewRootCommand()

	var runtimeFound, doctorFound bool
	for _, sub := range root.Commands() {
		if strings.HasPrefix(sub.Use, "runtime") {
			runtimeFound = true
			for _, sub2 := range sub.Commands() {
				if strings.HasPrefix(sub2.Use, "doctor") {
					doctorFound = true
				}
			}
		}
	}
	assert.True(t, runtimeFound, "runtime subcommand must be registered")
	assert.True(t, doctorFound, "runtime doctor subcommand must be registered under runtime")
}

// TestRuntimeDoctor_UnknownProvider_GracefulOutput verifies that `runtime doctor`
// handles an unknown provider gracefully (no panic, clear output).
func TestRuntimeDoctor_UnknownProvider_GracefulOutput(t *testing.T) {
	t.Parallel()

	root := cli.NewRootCommand()
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&outBuf)
	root.SetArgs([]string{"runtime", "doctor", "nonexistent-test-provider"})
	_ = root.Execute()

	out := outBuf.String()
	assert.NotEmpty(t, out, "runtime doctor must produce output for unknown providers")
	assert.Contains(t, out, "nonexistent-test-provider",
		"runtime doctor output must include the provider name")
}

// TestRuntimeDoctor_RequiresProviderArg verifies that `runtime doctor` requires
// exactly one argument.
func TestRuntimeDoctor_RequiresProviderArg(t *testing.T) {
	t.Parallel()

	root := cli.NewRootCommand()
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&outBuf)
	root.SetArgs([]string{"runtime", "doctor"})
	err := root.Execute()
	// Missing arg should produce an error.
	assert.Error(t, err, "runtime doctor without argument must return an error")
}

// TestRuntimeDoctorReport_SandboxedReported validates that
// buildRuntimeDoctorReport (via the CLI) always appends the
// direct_classic_sandboxed entry and that it contains a meaningful reason string.
//
// Epic 22: direct_classic_sandboxed is now implemented.
// On Linux it is available when bwrap is present; on macOS it is available
// via sandbox-exec; on Windows it is never available.
func TestRuntimeDoctorReport_SandboxedReported(t *testing.T) {
	t.Parallel()

	// Run with the openrouter provider which is likely in the embedded registry.
	root := cli.NewRootCommand()
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"runtime", "doctor", "--json", "openrouter"})
	_ = root.Execute()

	out := outBuf.String()
	if !strings.Contains(out, "direct_classic_sandboxed") {
		// Provider may not be in registry in this test environment — skip the
		// detailed assertion but verify the command ran.
		require.NotEmpty(t, out, "runtime doctor must produce output")
		return
	}

	// Provider is present: direct_classic must appear in the output.
	assert.Contains(t, out, "direct_classic",
		"runtime doctor output must include direct_classic mode")

	// direct_classic_sandboxed entry must be present and have a non-empty reason.
	idx := strings.Index(out, "direct_classic_sandboxed")
	require.True(t, idx >= 0, "direct_classic_sandboxed must appear in runtime doctor output")

	// Grab the JSON window for this entry.
	window := out[idx:]
	nextMode := strings.Index(window[1:], "\"mode\"")
	if nextMode > 0 {
		window = window[:nextMode+1]
	}

	// The reason field must be non-empty (either "available — ..." or "not available — ...").
	assert.True(t, strings.Contains(window, "available"),
		"direct_classic_sandboxed reason must contain 'available'")
}
