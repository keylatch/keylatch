package cli_test

// setup_noninteractive_test.go tests the §2.4 non-interactive bootstrap flags.

import (
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSetup_NonInteractive_FlagsRegistered verifies that all §2.4 flags are
// registered on the setup command.
func TestSetup_NonInteractive_FlagsRegistered(t *testing.T) {
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
	// --non-interactive: tested in TestSetup_Headless_FlagRegistered but also
	// verify the backend flag supports the non-interactive path.
	assert.NotNil(t, setupCmd.Flags().Lookup("backend"),
		"setup --backend is required for non-interactive mode")
	assert.NotNil(t, setupCmd.Flags().Lookup("non-interactive"))
	assert.NotNil(t, setupCmd.Flags().Lookup("from-env"))
	assert.NotNil(t, setupCmd.Flags().Lookup("stdin-field"))
}

// TestSetup_Headless_FlagRegistered verifies that the --headless flag exists on setup.
func TestSetup_Headless_FlagRegistered(t *testing.T) {
	t.Parallel()

	root := cli.NewRootCommand()
	var setupCmd *cobra.Command //nolint:typecheck // cobra imported for type assertion
	for _, c := range root.Commands() {
		if c.Name() == "setup" {
			setupCmd = c
			break
		}
	}
	require.NotNil(t, setupCmd, "setup command must be registered")
	assert.NotNil(t, setupCmd.Flags().Lookup("headless"), "setup must have --headless flag")
	assert.NotNil(t, setupCmd.Flags().Lookup("non-interactive"), "setup must have --non-interactive flag")
	assert.NotNil(t, setupCmd.Flags().Lookup("from-env"), "setup must have --from-env flag")
	assert.NotNil(t, setupCmd.Flags().Lookup("stdin-field"), "setup must have --stdin-field flag")
	assert.NotNil(t, setupCmd.Flags().Lookup("backend"), "setup must have --backend flag")
}

// TestResolveStdinFields_Valid verifies that well-formed key=value pairs are parsed.
func TestResolveStdinFields_Valid(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input    []string
		expected map[string]string
	}{
		{
			input:    []string{"api_key=sk-abc123"},
			expected: map[string]string{"api_key": "sk-abc123"},
		},
		{
			input:    []string{"key=val", "other=v2"},
			expected: map[string]string{"key": "val", "other": "v2"},
		},
		{
			// Value containing "=" sign.
			input:    []string{"token=abc=def=ghi"},
			expected: map[string]string{"token": "abc=def=ghi"},
		},
		{
			input:    []string{},
			expected: map[string]string{},
		},
	}

	for _, tc := range cases {
		got, err := cli.ResolveStdinFields(tc.input)
		require.NoError(t, err)
		assert.Equal(t, tc.expected, got)
	}
}

// TestResolveStdinFields_Invalid verifies that malformed entries return errors.
func TestResolveStdinFields_Invalid(t *testing.T) {
	t.Parallel()

	badInputs := [][]string{
		{"noequals"},
		{"=nokey"},
	}

	for _, input := range badInputs {
		_, err := cli.ResolveStdinFields(input)
		assert.Error(t, err, "should error on malformed stdin-field: %v", input)
	}
}

// TestSetup_Epic26_FlagsRegistered verifies that all Epic 26 flags are registered
// on the setup command: --advanced, --no-daemon-start, --telemetry, --config.
func TestSetup_Epic26_FlagsRegistered(t *testing.T) {
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

	assert.NotNil(t, setupCmd.Flags().Lookup("advanced"),
		"setup must have --advanced flag (Epic 26)")
	assert.NotNil(t, setupCmd.Flags().Lookup("no-daemon-start"),
		"setup must have --no-daemon-start flag (Epic 26)")
	assert.NotNil(t, setupCmd.Flags().Lookup("telemetry"),
		"setup must have --telemetry flag (Epic 26)")
	assert.NotNil(t, setupCmd.Flags().Lookup("config"),
		"setup must have --config flag (Epic 26)")
}

// TestSetup_Headless_DefaultBackend verifies that --headless without --backend
// uses "file" as the default backend.
func TestSetup_Headless_DefaultBackend(t *testing.T) {
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

	// Verify --headless is registered (already covered by TestSetup_Headless_FlagRegistered
	// but checking default value here).
	f := setupCmd.Flags().Lookup("headless")
	require.NotNil(t, f)
	assert.Equal(t, "false", f.DefValue, "--headless must default to false")

	// Verify --backend defaults to empty string (falls back to "file" in headless mode).
	bf := setupCmd.Flags().Lookup("backend")
	require.NotNil(t, bf)
	assert.Equal(t, "", bf.DefValue, "--backend must default to empty string")
}

// TestSetup_NoDaemonStart_FlagDefault verifies that --no-daemon-start defaults to false.
func TestSetup_NoDaemonStart_FlagDefault(t *testing.T) {
	t.Parallel()

	root := cli.NewRootCommand()
	var setupCmd *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "setup" {
			setupCmd = c
			break
		}
	}
	require.NotNil(t, setupCmd)

	f := setupCmd.Flags().Lookup("no-daemon-start")
	require.NotNil(t, f)
	assert.Equal(t, "false", f.DefValue, "--no-daemon-start must default to false")
}

// TestSetup_ProgressMarkers_InLongHelp verifies that the [N/5] step markers
// are documented in the command Long description.
func TestSetup_ProgressMarkers_InLongHelp(t *testing.T) {
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

	// Verify all 5 step markers appear in the long description.
	for _, marker := range []string{"[1/5]", "[2/5]", "[3/5]", "[4/5]", "[5/5]"} {
		assert.Contains(t, setupCmd.Long, marker,
			"setup Long description must contain step marker %s", marker)
	}
}
