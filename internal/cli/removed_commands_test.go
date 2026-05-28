package cli_test

// removed_commands_test.go — T-10-04 / S-INV-4b
//
// Regression tests asserting that keylatch inject and --runtime direct_classic
// do not exist in v1.0.0.
//
// The exec-based tests require the keylatch binary to be on PATH and are skipped
// when the binary is not available (e.g. in unit-test-only CI runs).
// The cobra-based tests run unconditionally and verify the command tree.

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/runtime"
	"github.com/spf13/cobra"
)

// findCmd looks up a direct subcommand of root by its Use prefix.
// This helper is shared across multiple test files in the cli_test package.
func findCmd(root *cobra.Command, usePrefix string) *cobra.Command {
	for _, cmd := range root.Commands() {
		if len(cmd.Use) >= len(usePrefix) && cmd.Use[:len(usePrefix)] == usePrefix {
			return cmd
		}
	}
	return nil
}

// TestInjectCommandNotRegistered verifies that the inject command is not
// registered in the cobra root command tree (S-INV-4b).
func TestInjectCommandNotRegistered(t *testing.T) {
	root := cli.NewRootCommand()
	cmd := findCmd(root, "inject ")
	if cmd != nil {
		t.Error("S-INV-4b: 'keylatch inject' must not be registered in v1.0.0 — command still exists")
	}
}

// TestDirectClassicNotInAllModes verifies that direct_classic is absent from
// runtime.AllModes (S-INV-4b, T-10-03). direct_classic_sandboxed is intentionally
// present — it was reinstated as a new sibling mode in EPIC-24.
func TestDirectClassicNotInAllModes(t *testing.T) {
	// Only direct_classic is permanently removed; direct_classic_sandboxed is active.
	forbidden := []runtime.RuntimeMode{"direct_classic"}
	for _, mode := range forbidden {
		for _, m := range runtime.AllModes {
			if m == mode {
				t.Errorf("S-INV-4b: runtime.AllModes still contains permanently removed mode %q", mode)
			}
		}
	}
}

// TestInjectCommandRemoved is an end-to-end test that verifies that
// running 'keylatch inject ...' returns a non-zero exit code (cobra unknown command).
// Skipped when the keylatch binary is not on PATH.
func TestInjectCommandRemoved(t *testing.T) {
	if _, err := exec.LookPath("keylatch"); err != nil {
		t.Skip("keylatch binary not on PATH — skipping end-to-end inject removal test")
	}
	for _, env := range []string{"", "CLAUDE_CODE=1", "CODEX_ENV=1"} {
		t.Run("env="+env, func(t *testing.T) {
			cmd := exec.Command("keylatch", "inject", "keylatch-e2e")
			if env != "" {
				cmd.Env = append(cmd.Environ(), env)
			}
			err := cmd.Run()
			if err == nil {
				t.Errorf("S-INV-4b: 'keylatch inject' with env=%q exited 0 — expected non-zero", env)
			}
		})
	}
}

// TestDirectClassicRuntimeRemoved verifies that --runtime direct_classic
// exits with code RuntimeNotAvailable (5) and prints a hint to use gateway_typed.
// Skipped when the keylatch binary is not on PATH.
func TestDirectClassicRuntimeRemoved(t *testing.T) {
	if _, err := exec.LookPath("keylatch"); err != nil {
		t.Skip("keylatch binary not on PATH — skipping end-to-end direct_classic removal test")
	}
	cmd := exec.Command("keylatch", "run", "--runtime", "direct_classic", "keylatch-e2e", "--", "echo", "hi")
	out, _ := cmd.CombinedOutput()
	exitCode := cmd.ProcessState.ExitCode()
	if exitCode != exitcode.RuntimeNotAvailable {
		t.Errorf("S-INV-4b: expected exit %d (RuntimeNotAvailable), got %d; output: %s",
			exitcode.RuntimeNotAvailable, exitCode, out)
	}
	if !strings.Contains(string(out), "gateway_typed") {
		t.Errorf("S-INV-4b: expected hint to use gateway_typed in output, got: %s", out)
	}
}
