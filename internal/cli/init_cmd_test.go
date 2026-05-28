package cli_test

// init_cmd_test.go tests §2.4 keylatch init --ci command.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInitCI_Registered verifies that `keylatch init` with a `ci` subcommand
// is registered in the command tree.
func TestInitCI_Registered(t *testing.T) {
	t.Parallel()

	root := cli.NewRootCommand()
	var initCmd *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "init" {
			initCmd = c
			break
		}
	}
	require.NotNil(t, initCmd, "init command must be registered")

	var ciCmd *cobra.Command
	for _, c := range initCmd.Commands() {
		if c.Name() == "ci" {
			ciCmd = c
			break
		}
	}
	require.NotNil(t, ciCmd, "init ci subcommand must be registered")
	assert.NotNil(t, ciCmd.Flags().Lookup("write"), "init ci must have --write flag")
	assert.NotNil(t, ciCmd.Flags().Lookup("config"), "init ci must have --config flag")
	assert.NotNil(t, ciCmd.Flags().Lookup("force"), "init ci must have --force flag")
}

// TestInitCI_WritesConfigSkeleton verifies that `keylatch init ci --config=<path>`
// writes a keylatch.yaml skeleton to the specified path.
func TestInitCI_WritesConfigSkeleton(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "keylatch.yaml")

	root := cli.NewRootCommand()
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"init", "ci", "--config=" + configPath})

	err := root.Execute()
	// os.Exit is not called by init ci — it returns errors normally.
	require.NoError(t, err)

	data, readErr := os.ReadFile(configPath)
	require.NoError(t, readErr, "keylatch.yaml should have been written")

	content := string(data)
	assert.Contains(t, content, "backend:", "skeleton must contain backend field")
	assert.Contains(t, content, "default_namespace:", "skeleton must contain default_namespace")
	assert.Contains(t, content, "audit:", "skeleton must contain audit section")
	// Verify it is comment-annotated.
	assert.Contains(t, content, "#", "skeleton must be comment-annotated")
}

// TestInitCI_Idempotent verifies that running init ci twice does not overwrite
// an existing keylatch.yaml (without --force).
func TestInitCI_Idempotent(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "keylatch.yaml")

	// Write a custom file first.
	customContent := "# custom\nbackend: op\n"
	require.NoError(t, os.WriteFile(configPath, []byte(customContent), 0o644))

	root := cli.NewRootCommand()
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"init", "ci", "--config=" + configPath})

	require.NoError(t, root.Execute())

	// File must not have been overwritten.
	data, _ := os.ReadFile(configPath)
	assert.Equal(t, customContent, string(data),
		"init ci must not overwrite existing keylatch.yaml without --force")

	// Output should mention "already exists".
	assert.Contains(t, outBuf.String(), "already exists")
}

// TestInitCI_Force_OverwritesExisting verifies --force overwrites the file.
func TestInitCI_Force_OverwritesExisting(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "keylatch.yaml")

	require.NoError(t, os.WriteFile(configPath, []byte("# old\n"), 0o644))

	root := cli.NewRootCommand()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"init", "ci", "--config=" + configPath, "--force"})

	require.NoError(t, root.Execute())

	data, _ := os.ReadFile(configPath)
	assert.NotEqual(t, "# old\n", string(data), "init ci --force must overwrite the file")
	assert.Contains(t, string(data), "backend:", "overwritten file must be the skeleton")
}

// TestInitCI_PrintsGitHubActionsSnippet verifies that stdout contains a GitHub
// Actions snippet when --write is not passed.
func TestInitCI_PrintsGitHubActionsSnippet(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "keylatch.yaml")

	root := cli.NewRootCommand()
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"init", "ci", "--config=" + configPath})

	require.NoError(t, root.Execute())

	out := outBuf.String()
	assert.True(t,
		strings.Contains(out, "github-actions") || strings.Contains(out, "GitHub Actions") || strings.Contains(out, "keylatch-ci"),
		"stdout should contain GitHub Actions snippet, got: %q", out)
}

// TestInitCI_PrintsGetStartedHint verifies that init ci prints the §2.6 "Get started" line.
func TestInitCI_PrintsGetStartedHint(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "keylatch.yaml")

	root := cli.NewRootCommand()
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"init", "ci", "--config=" + configPath})

	require.NoError(t, root.Execute())

	assert.Contains(t, outBuf.String(), "Get started: keylatch.dev/start")
}
