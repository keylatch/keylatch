package cli_test

// doctor_repair_test.go tests §2.5 doctor --repair and --yes flags and
// the doctor hint wiring.

import (
	"bytes"
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDoctor_FlagsRegistered verifies that --repair and --yes are wired into
// the doctor command.
func TestDoctor_FlagsRegistered(t *testing.T) {
	t.Parallel()

	root := cli.NewRootCommand()
	var doctorCmd *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "doctor" {
			doctorCmd = c
			break
		}
	}
	require.NotNil(t, doctorCmd, "doctor command must be registered")
	assert.NotNil(t, doctorCmd.Flags().Lookup("repair"), "doctor must have --repair flag")
	assert.NotNil(t, doctorCmd.Flags().Lookup("yes"), "doctor must have --yes flag")
}

// TestDoctorHint_NotEmpty verifies that the exported DoctorHint constant is
// non-empty and mentions `keylatch doctor`.
func TestDoctorHint_NotEmpty(t *testing.T) {
	t.Parallel()
	assert.NotEmpty(t, cli.DoctorHint)
	assert.Contains(t, cli.DoctorHint, "keylatch doctor")
}

// TestIsDoctorHintSuppressed_DoctorCmd verifies that the hint is suppressed for
// the doctor command itself.
func TestIsDoctorHintSuppressed_DoctorCmd(t *testing.T) {
	t.Parallel()

	root := cli.NewRootCommand()
	var doctorCmd *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "doctor" {
			doctorCmd = c
			break
		}
	}
	require.NotNil(t, doctorCmd)
	assert.True(t, cli.IsDoctorHintSuppressed(doctorCmd),
		"doctor hint should be suppressed for the doctor command itself")
}

// TestIsDoctorHintSuppressed_CompletionCmd verifies that the hint is suppressed
// for shell completion commands.
func TestIsDoctorHintSuppressed_CompletionCmd(t *testing.T) {
	t.Parallel()

	root := cli.NewRootCommand()
	var completionCmd *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "completion" {
			completionCmd = c
			break
		}
	}
	if completionCmd == nil {
		t.Skip("completion command not registered")
	}
	assert.True(t, cli.IsDoctorHintSuppressed(completionCmd),
		"doctor hint should be suppressed for completion command")
}

// TestDoctor_RepairQuietWithoutYes_RejectedFastNoHang is the review
// Finding-005 regression test: `doctor --repair --quiet` without --yes used
// to write its confirmation prompt to a discarded writer while still
// blocking on real stdin — invisible and indistinguishable from a hang. It
// must now fail fast with a usage error instead of reading stdin at all.
func TestDoctor_RepairQuietWithoutYes_RejectedFastNoHang(t *testing.T) {
	t.Parallel()

	root := cli.NewRootCommand()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	// Deliberately no stdin reader set — if the command tried to read a
	// prompt response, cobra's default os.Stdin would be used and this
	// test would hang forever instead of failing fast.
	root.SetArgs([]string{"doctor", "--repair", "--quiet"})

	err := root.Execute()
	require.Error(t, err, "doctor --repair --quiet without --yes must be rejected")
	assert.Contains(t, err.Error(), "--yes")
}

// Note: there is no in-process "quiet+yes is allowed" companion test here.
// doctor's RunE always terminates via os.Exit(exitCode) at the very end
// (every exit code, including 0), so calling root.Execute() with the
// "doctor" subcommand in-process would kill the test binary itself once
// past the early --repair --quiet-without---yes rejection checked above.
// The allowed-combination path is covered end-to-end (subprocess, safe) by
// TestE2E_Doctor_RepairQuietWithYes_DoesNotHang in cmd/keylatch/main_e2e_test.go.

// TestDoctor_VerboseFlagRegistered verifies that --verbose is wired to the doctor command.
func TestDoctor_VerboseFlagRegistered(t *testing.T) {
	t.Parallel()

	root := cli.NewRootCommand()
	var doctorCmd *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "doctor" {
			doctorCmd = c
			break
		}
	}
	require.NotNil(t, doctorCmd)
	assert.NotNil(t, doctorCmd.Flags().Lookup("verbose"), "doctor must have --verbose flag")
	assert.NotNil(t, doctorCmd.Flags().Lookup("json"), "doctor must have --json flag")
	assert.NotNil(t, doctorCmd.Flags().Lookup("redact-paths"), "doctor must have --redact-paths flag")
}
