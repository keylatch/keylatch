package cli_test

// runtime_doctor_test.go verifies the `runtime doctor` output.

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

// TestRuntimeDoctorReport_NoRemovedRuntime validates that the report never
// lists the removed classic sandboxed runtime.
func TestRuntimeDoctorReport_NoRemovedRuntime(t *testing.T) {
	t.Parallel()

	root := cli.NewRootCommand()
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"runtime", "doctor", "--json", "openrouter"})
	_ = root.Execute()

	out := outBuf.String()
	require.NotEmpty(t, out, "runtime doctor must produce output")
	assert.False(t, strings.Contains(out, "direct_classic"),
		"runtime doctor output must not include removed runtimes")
}
