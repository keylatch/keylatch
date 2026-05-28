package cli_test

import (
	"bytes"
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// experimentalCommandNames lists the commands that must be gated behind
// KEYLATCH_EXPERIMENTAL=1.
//
// Epic 25: all commands have graduated to production; the gate is now empty.
var experimentalCommandNames = []string{
	// (empty — all commands have graduated)
}

// graduatedCommandNames lists commands that were formerly experimental but have
// since been promoted to top-level (registered unconditionally).
var graduatedCommandNames = []string{
	"broker",
	"call",
	"proxy",
	"sandbox",
	"approve",
	"deny",
}

// TestExperimentalGate_CommandsAbsentWhenUnset asserts that gated commands
// are completely absent when KEYLATCH_EXPERIMENTAL is not set.
// (Currently empty — all commands have graduated to production.)
func TestExperimentalGate_CommandsAbsentWhenUnset(t *testing.T) {
	t.Setenv("KEYLATCH_EXPERIMENTAL", "")
	root := cli.NewRootCommand()

	registered := make(map[string]bool)
	for _, cmd := range root.Commands() {
		registered[cmd.Name()] = true
	}

	for _, name := range experimentalCommandNames {
		assert.False(t, registered[name],
			"experimental command %q must not be registered when KEYLATCH_EXPERIMENTAL is unset", name)
	}
}

// TestExperimentalGate_CommandsPresentWhenEnabled asserts that graduated
// commands (proxy, sandbox, call, broker, approve, deny) are always present.
func TestExperimentalGate_CommandsPresentWhenEnabled(t *testing.T) {
	t.Setenv("KEYLATCH_EXPERIMENTAL", "1")
	root := cli.NewRootCommand()

	registered := make(map[string]bool)
	for _, cmd := range root.Commands() {
		registered[cmd.Name()] = true
	}

	for _, name := range experimentalCommandNames {
		assert.True(t, registered[name],
			"gated command %q must be registered when KEYLATCH_EXPERIMENTAL=1", name)
	}
	for _, name := range graduatedCommandNames {
		assert.True(t, registered[name],
			"graduated command %q must always be registered", name)
	}
}

// TestGraduatedCommands_AlwaysPresent asserts that commands graduated from
// experimental are registered regardless of KEYLATCH_EXPERIMENTAL.
func TestGraduatedCommands_AlwaysPresent(t *testing.T) {
	for _, env := range []string{"", "0", "1"} {
		env := env
		t.Run("KEYLATCH_EXPERIMENTAL="+env, func(t *testing.T) {
			t.Setenv("KEYLATCH_EXPERIMENTAL", env)
			root := cli.NewRootCommand()
			registered := make(map[string]bool)
			for _, cmd := range root.Commands() {
				registered[cmd.Name()] = true
			}
			for _, name := range graduatedCommandNames {
				assert.True(t, registered[name],
					"graduated command %q must always be registered (KEYLATCH_EXPERIMENTAL=%s)", name, env)
			}
		})
	}
}

// TestExperimentalCmd_AlwaysVisible asserts that `keylatch experimental` is
// always present, regardless of the KEYLATCH_EXPERIMENTAL variable.
func TestExperimentalCmd_AlwaysVisible(t *testing.T) {
	for _, env := range []string{"", "0", "1"} {
		env := env
		t.Run("KEYLATCH_EXPERIMENTAL="+env, func(t *testing.T) {
			t.Setenv("KEYLATCH_EXPERIMENTAL", env)
			root := cli.NewRootCommand()
			registered := make(map[string]bool)
			for _, cmd := range root.Commands() {
				registered[cmd.Name()] = true
			}
			assert.True(t, registered["experimental"],
				"'keylatch experimental' must always be registered")
		})
	}
}

// TestExperimentalCmd_PrintsNoGatedMessage asserts that `keylatch experimental`
// output states no commands are currently gated (Epic 25).
func TestExperimentalCmd_PrintsNoGatedMessage(t *testing.T) {
	t.Setenv("KEYLATCH_EXPERIMENTAL", "")
	root := cli.NewRootCommand()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"experimental"})
	err := root.Execute()
	require.NoError(t, err)

	out := buf.String()
	// Epic 25: all commands graduated — output must confirm no gated commands.
	assert.Contains(t, out, "No experimental commands are currently gated")
	assert.Contains(t, out, "KEYLATCH_EXPERIMENTAL=1")
}

// TestExperimentalCmd_ListsGatedCommands asserts that `keylatch experimental`
// output mentions the KEYLATCH_EXPERIMENTAL=1 enable instruction.
// (With an empty experimentalCmds list, the list body will be empty.)
func TestExperimentalCmd_ListsGatedCommands(t *testing.T) {
	t.Setenv("KEYLATCH_EXPERIMENTAL", "")
	root := cli.NewRootCommand()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"experimental"})
	err := root.Execute()
	require.NoError(t, err)

	out := buf.String()
	// All experimental commands have graduated — the list is empty but the
	// KEYLATCH_EXPERIMENTAL=1 instruction must still appear.
	assert.Contains(t, out, "KEYLATCH_EXPERIMENTAL=1")
}

// TestGraduatedCommands_PresentWithoutEnvVar asserts all 6 graduated commands
// appear as registered subcommands with KEYLATCH_EXPERIMENTAL unset (Epic 25).
func TestGraduatedCommands_PresentWithoutEnvVar(t *testing.T) {
	t.Setenv("KEYLATCH_EXPERIMENTAL", "")
	root := cli.NewRootCommand()

	registered := make(map[string]bool)
	for _, cmd := range root.Commands() {
		registered[cmd.Name()] = true
	}

	for _, name := range graduatedCommandNames {
		assert.True(t, registered[name],
			"graduated command %q must appear in keylatch --help WITHOUT setting KEYLATCH_EXPERIMENTAL", name)
	}
}

// TestGraduatedCommands_PresentWithEnvVar asserts all 6 graduated commands
// appear as registered subcommands with KEYLATCH_EXPERIMENTAL=1 (Epic 25).
func TestGraduatedCommands_PresentWithEnvVar(t *testing.T) {
	t.Setenv("KEYLATCH_EXPERIMENTAL", "1")
	root := cli.NewRootCommand()

	registered := make(map[string]bool)
	for _, cmd := range root.Commands() {
		registered[cmd.Name()] = true
	}

	for _, name := range graduatedCommandNames {
		assert.True(t, registered[name],
			"graduated command %q must appear when KEYLATCH_EXPERIMENTAL=1", name)
	}
}

// TestExperimentalGate_BannerInLongDescription asserts that any remaining
// gated commands contain the experimental banner in their Long description.
// (Currently no gated commands remain — this is a future-proof test skeleton.)
func TestExperimentalGate_BannerInLongDescription(t *testing.T) {
	t.Setenv("KEYLATCH_EXPERIMENTAL", "1")
	root := cli.NewRootCommand()
	_ = root

	for _, name := range experimentalCommandNames {
		name := name
		t.Run(name, func(t *testing.T) {
			cmd, _, err := root.Find([]string{name})
			require.NoError(t, err)
			require.NotEqual(t, root.Name(), cmd.Name(),
				"command %q should be findable when KEYLATCH_EXPERIMENTAL=1", name)
			assert.True(t,
				len(cmd.Long) > 0,
				"command %q must have a non-empty Long description", name)
		})
	}
}

// TestExperimentalGate_CommandNotFoundWithoutEnv asserts that cobra's Find
// returns root (not the command) when the gate is closed, which means the
// command is genuinely absent.
// (Currently no gated commands — verify graduated commands are still findable.)
func TestExperimentalGate_CommandNotFoundWithoutEnv(t *testing.T) {
	t.Setenv("KEYLATCH_EXPERIMENTAL", "")
	root := cli.NewRootCommand()

	// Gated commands: none currently.
	for _, name := range experimentalCommandNames {
		name := name
		t.Run(name, func(t *testing.T) {
			found, _, _ := root.Find([]string{name})
			assert.Equal(t, root.Name(), found.Name(),
				"Find(%q) should return root when KEYLATCH_EXPERIMENTAL is unset", name)
		})
	}

	// Graduated commands must be findable even without KEYLATCH_EXPERIMENTAL.
	for _, name := range graduatedCommandNames {
		name := name
		t.Run("graduated/"+name, func(t *testing.T) {
			found, _, _ := root.Find([]string{name})
			assert.Equal(t, name, found.Name(),
				"graduated command %q must be findable without KEYLATCH_EXPERIMENTAL", name)
		})
	}
}
