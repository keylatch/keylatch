package cli_test

// audit_tail_cmd_test.go tests duration parsing and install-guard/verify flag wiring.

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseDuration_ValidInputs verifies that parseDuration handles all
// documented formats for `keylatch audit since <duration>`.
func TestParseDuration_ValidInputs(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
	}{
		{"1h", 1 * time.Hour},
		{"24h", 24 * time.Hour},
		{"30m", 30 * time.Minute},
		{"7d", 7 * 24 * time.Hour},
		{"30d", 30 * 24 * time.Hour},
		{"1d", 24 * time.Hour},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := cli.ParseDurationPublic(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseDuration_InvalidInputs(t *testing.T) {
	// "-1h" is technically valid Go duration (negative), but "0d" and "abc" are not.
	invalid := []string{"", "abc", "0d", "1dd", "-1h"}
	for _, s := range invalid {
		t.Run(s, func(t *testing.T) {
			_, err := cli.ParseDurationPublic(s)
			assert.Error(t, err, "expected error for input %q", s)
		})
	}
}

// TestInstallGuardCmd_RegisteredInRootTree verifies that `install-guard` is
// registered in the command tree and returns a usage error when called with no args.
func TestInstallGuardCmd_RegisteredInRootTree(t *testing.T) {
	root := cli.NewRootCommand()
	var outBuf, errBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs([]string{"install-guard"})
	err := root.ExecuteContext(context.Background())
	// Should fail with a usage error (missing required positional argument).
	assert.Error(t, err, "install-guard without args must return an error")
}

// TestVerifyCmd_SelfFlagRegistered verifies that `verify --self` is recognized
// by the command tree (not "unknown flag").
func TestVerifyCmd_SelfFlagRegistered(t *testing.T) {
	root := cli.NewRootCommand()
	verifyCmd, _, err := root.Find([]string{"verify"})
	require.NoError(t, err)
	require.NotNil(t, verifyCmd)
	flag := verifyCmd.Flags().Lookup("self")
	require.NotNil(t, flag, "--self flag must be registered on the verify command")
	assert.Equal(t, "bool", flag.Value.Type())
}

// TestAuditSinceCmd_RegisteredInAuditTree verifies that `audit since` is
// a subcommand of `audit`.
func TestAuditSinceCmd_RegisteredInAuditTree(t *testing.T) {
	root := cli.NewRootCommand()
	auditCmd, _, err := root.Find([]string{"audit"})
	require.NoError(t, err)
	require.NotNil(t, auditCmd)

	sinceCmd, _, err := auditCmd.Find([]string{"since"})
	require.NoError(t, err)
	require.NotNil(t, sinceCmd, "audit since subcommand must be registered")
}

// TestAuditTailCmd_RegisteredInAuditTree verifies that `audit tail` is registered.
func TestAuditTailCmd_RegisteredInAuditTree(t *testing.T) {
	root := cli.NewRootCommand()
	auditCmd, _, err := root.Find([]string{"audit"})
	require.NoError(t, err)
	require.NotNil(t, auditCmd)

	tailCmd, _, err := auditCmd.Find([]string{"tail"})
	require.NoError(t, err)
	require.NotNil(t, tailCmd, "audit tail subcommand must be registered")
}

// TestSecurityCmd_PrintsInvariants verifies that `keylatch security` prints
// the five invariant bullets.
func TestSecurityCmd_PrintsInvariants(t *testing.T) {
	root := cli.NewRootCommand()
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"security"})
	err := root.ExecuteContext(context.Background())
	require.NoError(t, err)

	out := outBuf.String()
	assert.Contains(t, out, "secrets never touch agent memory")
	assert.Contains(t, out, "Every secret use is logged")
	assert.Contains(t, out, "Revoking access is instant")
	assert.Contains(t, out, "Approvals expire automatically")
	assert.Contains(t, out, "No secret leaves your machine")
	assert.Contains(t, out, "audit tail")
	assert.Contains(t, out, "doctor")
}
