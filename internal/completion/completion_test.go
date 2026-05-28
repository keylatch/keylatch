package completion_test

import (
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/keylatch/keylatch/internal/completion"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func rootCmd() interface {
	// Returns the root command via cli.
} {
	return nil
}

func TestGenerate_Zsh(t *testing.T) {
	root := cli.NewRootCommand()
	out, err := completion.Generate(completion.Zsh, root)
	require.NoError(t, err)
	// Must start with #compdef keylatch.
	lines := strings.Split(out, "\n")
	assert.Equal(t, "#compdef keylatch", lines[0])
	// Must mention known subcommands.
	assert.Contains(t, out, "doctor")
	assert.Contains(t, out, "bootstrap")
	// Must not contain secret-like tokens.
	assert.NotContains(t, out, "password")
	assert.NotContains(t, out, "sk-")
}

func TestGenerate_Bash(t *testing.T) {
	root := cli.NewRootCommand()
	out, err := completion.Generate(completion.Bash, root)
	require.NoError(t, err)
	assert.Contains(t, out, "_keylatch_completions")
	assert.Contains(t, out, "complete -F")
	assert.Contains(t, out, "doctor")
}

func TestGenerate_Fish(t *testing.T) {
	root := cli.NewRootCommand()
	out, err := completion.Generate(completion.Fish, root)
	require.NoError(t, err)
	assert.Contains(t, out, "complete -c keylatch")
	assert.Contains(t, out, "doctor")
}

func TestGenerate_PowerShell(t *testing.T) {
	root := cli.NewRootCommand()
	out, err := completion.Generate(completion.PowerShell, root)
	require.NoError(t, err)
	assert.Contains(t, out, "Register-ArgumentCompleter")
	assert.Contains(t, out, "doctor")
}

func TestGenerate_UnknownShell(t *testing.T) {
	root := cli.NewRootCommand()
	_, err := completion.Generate("fish2", root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported shell")
}

func TestGenerate_AllSubcommandsPresent(t *testing.T) {
	root := cli.NewRootCommand()
	// Check that all registered subcommands appear in zsh output.
	out, err := completion.Generate(completion.Zsh, root)
	require.NoError(t, err)

	for _, sub := range root.Commands() {
		if sub.Hidden {
			continue
		}
		assert.Contains(t, out, sub.Name(),
			"zsh completion should mention subcommand %q", sub.Name())
	}
}

func TestGenerate_Zsh_RuntimeModes(t *testing.T) {
	root := cli.NewRootCommand()
	out, err := completion.Generate(completion.Zsh, root)
	require.NoError(t, err)

	for _, mode := range completion.RuntimeModes {
		assert.Contains(t, out, mode,
			"zsh completion should contain runtime mode %q", mode)
	}
}

func TestGenerate_Zsh_RuntimeSubcommands(t *testing.T) {
	root := cli.NewRootCommand()
	out, err := completion.Generate(completion.Zsh, root)
	require.NoError(t, err)

	assert.Contains(t, out, "runtime", "zsh completion should mention 'runtime' subcommand")
	assert.Contains(t, out, "proxy", "zsh completion should mention 'proxy' subcommand")
	assert.Contains(t, out, "sandbox", "zsh completion should mention 'sandbox' subcommand")
}
