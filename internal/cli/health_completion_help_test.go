package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealthCmd_HealthyStates(t *testing.T) {
	cfgDir := cbIsolate(t)

	out, _, err := cbRun(t, "health")
	require.NoError(t, err)
	assert.Equal(t, "config: not present (not bootstrapped)\nkeyring: not present (not bootstrapped)\nhealthy\n", out)

	_, _, err = cbRun(t, "setup", "--headless")
	require.NoError(t, err)
	out, _, err = cbRun(t, "health", "--probe-server")
	require.NoError(t, err)
	assert.Contains(t, out, "config: ok\nkeyring: ok\n")
	assert.Contains(t, out, "server: ")
	assert.True(t, strings.HasSuffix(out, "healthy\n"))

	krBytes, err := os.ReadFile(filepath.Join(cfgDir, "keyring", "keyring.json"))
	require.NoError(t, err)
	assert.NotContains(t, out, string(krBytes))
}

func TestCompletionCmd_Bash(t *testing.T) {
	cbIsolate(t)
	out, _, err := cbRun(t, "completion", "bash")
	require.NoError(t, err)
	assert.Contains(t, out, "keylatch")
	assert.Contains(t, out, "complete")
}

func TestRegisterExperimentalAliases_EnvToggle(t *testing.T) {
	root := &cobra.Command{Use: "root"}
	group := &cobra.Command{Use: "experimental"}

	t.Setenv("KEYLATCH_EXPERIMENTAL", "")
	registerExperimentalAliases(group, root)
	assert.Empty(t, group.Commands())

	t.Setenv("KEYLATCH_EXPERIMENTAL", "1")
	registerExperimentalAliases(group, root)
	assert.Len(t, group.Commands(), len(experimentalCmds), "only listed experimental commands are aliased")
}

func TestHelpTopicParent(t *testing.T) {
	cbIsolate(t)
	out, _, err := cbRun(t, "help-topic")
	require.NoError(t, err)
	assert.Contains(t, out, "Available topics:")

	_, _, err = cbRun(t, "help-topic", "astrology")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown topic "astrology"`)
}

func TestResolveOperatingModeForDoctor(t *testing.T) {
	cbIsolate(t)
	assert.Equal(t, "standard", resolveOperatingModeForDoctor())

	t.Setenv("KEYLATCH_MODE", "canary")
	assert.Equal(t, "canary", resolveOperatingModeForDoctor())

	t.Setenv("KEYLATCH_MODE", "bogus")
	assert.Equal(t, "unknown", resolveOperatingModeForDoctor())
}
