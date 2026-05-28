package cli_test

// install_guard_windsurf_test.go tests the Windsurf and Antigravity
// install-guard paths that print shell-rc instructions (EPIC-25).

import (
	"bytes"
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInstallGuard_WindsurfPrintsShellRC verifies that `keylatch install-guard windsurf`
// prints the CREDENTIALS_LLM_SESSION=windsurf shell-rc snippet and exits cleanly.
func TestInstallGuard_WindsurfPrintsShellRC(t *testing.T) {
	root := cli.NewRootCommand()
	var outBuf, errBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs([]string{"install-guard", "windsurf"})

	err := root.ExecuteContext(context.Background())
	require.NoError(t, err, "install-guard windsurf must exit cleanly")

	out := outBuf.String()
	assert.Contains(t, out, "CREDENTIALS_LLM_SESSION=windsurf",
		"output must contain the env-var assignment")
	assert.Contains(t, out, "shell rc", "output must reference shell rc")
	assert.Contains(t, out, "export CREDENTIALS_LLM_SESSION=windsurf",
		"output must contain zsh/bash export snippet")
	assert.Contains(t, out, "set -Ux CREDENTIALS_LLM_SESSION windsurf",
		"output must contain fish snippet")
	assert.Contains(t, out, "restart your terminal",
		"output must instruct the user to restart their terminal")
	assert.Empty(t, errBuf.String(), "stderr must be empty on a clean run")
}

// TestInstallGuard_AntigravityPrintsShellRC verifies that `keylatch install-guard antigravity`
// prints the CREDENTIALS_LLM_SESSION=antigravity shell-rc snippet and exits cleanly.
func TestInstallGuard_AntigravityPrintsShellRC(t *testing.T) {
	root := cli.NewRootCommand()
	var outBuf, errBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs([]string{"install-guard", "antigravity"})

	err := root.ExecuteContext(context.Background())
	require.NoError(t, err, "install-guard antigravity must exit cleanly")

	out := outBuf.String()
	assert.Contains(t, out, "CREDENTIALS_LLM_SESSION=antigravity",
		"output must contain the env-var assignment")
	assert.Contains(t, out, "export CREDENTIALS_LLM_SESSION=antigravity",
		"output must contain zsh/bash export snippet")
	assert.Contains(t, out, "set -Ux CREDENTIALS_LLM_SESSION antigravity",
		"output must contain fish snippet")
	assert.Contains(t, out, "restart your terminal",
		"output must instruct the user to restart their terminal")
	assert.Empty(t, errBuf.String(), "stderr must be empty on a clean run")
}
