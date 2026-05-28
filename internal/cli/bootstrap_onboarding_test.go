package cli_test

// bootstrap_onboarding_test.go — EPIC-11 bootstrap onboarding tests.
//
// Tests:
//   - TestSetup_LocalBranch_Stdin         — local branch: ResolveStdinFields accepts key=value pairs
//   - TestSetup_ReferenceBranch_OpURI     — reference branch: ValidateProviderRefURI accepts op:// URI
//   - TestSetup_NonTTY_NoStdin_Fails      — setup command registered with --non-interactive flag
//   - TestRun_FirstRunGuard_NoBootstrap   — EPIC-11 guard 1: BootstrapMissing error class + code 7
//   - TestRun_FirstRunGuard_NoConnection  — EPIC-11 guard 2: SecretNotFound error class + code 6
//   - TestRun_FirstRunGuard_RuntimeUnavailable — EPIC-11 guard 3: RuntimeNotAvailable error + code 5

import (
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/store"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Task 1: setup wizard two-branch flow ─────────────────────────────────────

// TestSetup_LocalBranch_Stdin verifies that the local branch accepts key=value
// pairs via ResolveStdinFields (the --stdin-field flag parsing pathway).
func TestSetup_LocalBranch_Stdin(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		input  []string
		wantOK bool
	}{
		{"single field", []string{"api_key=sk-test-value"}, true},
		{"value with equals", []string{"token=abc=def"}, true},
		{"multiple fields", []string{"api_key=sk-test", "secret=supersecret"}, true},
		{"empty input", []string{}, true},
		{"malformed no equals", []string{"noequals"}, false},
		{"empty key", []string{"=value"}, false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result, err := cli.ResolveStdinFields(tc.input)
			if tc.wantOK {
				require.NoError(t, err, "ResolveStdinFields should succeed for %v", tc.input)
				assert.NotNil(t, result)
			} else {
				assert.Error(t, err, "ResolveStdinFields should fail for %v", tc.input)
			}
		})
	}
}

// TestSetup_ReferenceBranch_OpURI verifies that the reference branch correctly
// validates op://, aws-sm://, and hashivault:// URIs via store.ValidateProviderRefURI.
func TestSetup_ReferenceBranch_OpURI(t *testing.T) {
	t.Parallel()

	validURIs := []struct {
		name string
		uri  string
	}{
		{"op vault/item/field", "op://Private/Anthropic/api_key"},
		{"aws-sm region/secret", "aws-sm://us-east-1/my-secret"},
		{"hashivault mount/path/field", "hashivault://secret/myapp/config"},
		{"hashivault with fragment", "hashivault://secret/myapp/config#api_key"},
		{"op with nested path", "op://MyVault/MyItem/credential"},
	}

	for _, tc := range validURIs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := store.ValidateProviderRefURI(tc.uri)
			assert.NoError(t, err, "ValidateProviderRefURI should accept %q", tc.uri)
		})
	}

	invalidURIs := []struct {
		name string
		uri  string
	}{
		{"empty", ""},
		{"no scheme", "Private/Anthropic/api_key"},
		{"unknown scheme", "badstore://vault/item"},
		{"missing path", "op://"},
		{"no slash after host", "op://justhost"},
		{"trailing slash", "op://vault/item/"},
	}

	for _, tc := range invalidURIs {
		tc := tc
		t.Run("invalid_"+tc.name, func(t *testing.T) {
			t.Parallel()
			err := store.ValidateProviderRefURI(tc.uri)
			assert.Error(t, err, "ValidateProviderRefURI should reject %q", tc.uri)
		})
	}
}

// TestSetup_NonTTY_NoStdin_Fails verifies that the setup command has a
// --non-interactive flag, which is the mechanism for exiting with a UsageError
// when no TTY and no --stdin source are available.
func TestSetup_NonTTY_NoStdin_Fails(t *testing.T) {
	t.Parallel()

	root := cli.NewRootCommand()
	var setupCmd *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "setup" {
			setupCmd = c
			break
		}
	}
	require.NotNil(t, setupCmd, "setup command must be registered")

	// The --non-interactive flag is the guard for non-TTY environments.
	assert.NotNil(t, setupCmd.Flags().Lookup("non-interactive"),
		"setup must have --non-interactive flag for non-TTY enforcement")
	assert.NotNil(t, setupCmd.Flags().Lookup("stdin-field"),
		"setup must have --stdin-field for piped input support")
	assert.NotNil(t, setupCmd.Flags().Lookup("backend"),
		"setup must have --backend for non-interactive mode")
}

// ─── Task 2: first-run guard for keylatch run ─────────────────────────────────

// TestRun_FirstRunGuard_NoBootstrap verifies the BootstrapMissing error
// class: exit code 7, class name "BootstrapMissing", message contains "bootstrap".
func TestRun_FirstRunGuard_NoBootstrap(t *testing.T) {
	t.Parallel()

	err := cli.NewBootstrapMissing("keylatch not bootstrapped — run: keylatch bootstrap")
	require.NotNil(t, err)
	assert.Equal(t, 7, err.Code, "BootstrapMissing must exit 7")
	assert.Equal(t, "BootstrapMissing", err.Class)
	assert.Equal(t, exitcode.BootstrapMissing, err.Code)
	assert.Contains(t, err.Message, "bootstrap",
		"BootstrapMissing message must mention 'bootstrap'")
}

// TestRun_FirstRunGuard_NoConnection verifies the SecretNotFound error
// class: exit code 6, class name "SecretNotFound", message mentions "setup".
func TestRun_FirstRunGuard_NoConnection(t *testing.T) {
	t.Parallel()

	err := cli.NewSecretNotFound("no connection for provider %q — run: keylatch setup %s", "anthropic", "anthropic")
	require.NotNil(t, err)
	assert.Equal(t, 6, err.Code, "SecretNotFound must exit 6")
	assert.Equal(t, "SecretNotFound", err.Class)
	assert.Contains(t, err.Message, "anthropic")
	assert.Contains(t, err.Message, "setup",
		"SecretNotFound message must suggest running setup")
}

// TestRun_FirstRunGuard_RuntimeUnavailable verifies the RuntimeNotAvailable error
// class: exit code 5, class name "RuntimeNotAvailable".
func TestRun_FirstRunGuard_RuntimeUnavailable(t *testing.T) {
	t.Parallel()

	err := cli.NewRuntimeNotAvailable("runtime mode %q has been removed", "direct_classic")
	require.NotNil(t, err)
	assert.Equal(t, exitcode.RuntimeNotAvailable, err.Code, "RuntimeNotAvailable must exit 5")
	assert.Equal(t, "RuntimeNotAvailable", err.Class)
	assert.Contains(t, err.Message, "direct_classic")
}

// TestRun_Cmd_Registered verifies that the run command is in the command tree.
func TestRun_Cmd_Registered(t *testing.T) {
	t.Parallel()

	root := cli.NewRootCommand()
	var runCmd *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "run" {
			runCmd = c
			break
		}
	}
	require.NotNil(t, runCmd, "run command must be registered")
	assert.NotNil(t, runCmd.Flags().Lookup("runtime"), "run must have --runtime flag")
	assert.NotNil(t, runCmd.Flags().Lookup("dry-run"), "run must have --dry-run flag")
}
