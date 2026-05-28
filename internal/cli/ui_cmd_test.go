package cli_test

import (
	"bytes"
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUICmd_Registered(t *testing.T) {
	t.Parallel()
	root := cli.NewRootCommand()
	ui, _, err := root.Find([]string{"ui"})
	require.NoError(t, err)
	assert.Equal(t, "ui", ui.Name())
}

func TestUICmd_Flags(t *testing.T) {
	t.Parallel()
	root := cli.NewRootCommand()
	uiCmd, _, err := root.Find([]string{"ui"})
	require.NoError(t, err)

	assert.NotNil(t, uiCmd.Flags().Lookup("port"))
	assert.NotNil(t, uiCmd.Flags().Lookup("demo"))
	assert.NotNil(t, uiCmd.Flags().Lookup("no-open"))
	assert.NotNil(t, uiCmd.Flags().Lookup("unsafe-bind-all"))
	assert.NotNil(t, uiCmd.Flags().Lookup("scope"))
}

// TestApproveCmd_Registered verifies approve is registered unconditionally (Epic 23).
func TestApproveCmd_Registered(t *testing.T) {
	t.Parallel()
	root := cli.NewRootCommand()
	cmd, _, err := root.Find([]string{"approve"})
	require.NoError(t, err)
	assert.Equal(t, "approve", cmd.Name())
}

// TestDenyCmd_Registered verifies deny is registered unconditionally (Epic 23).
func TestDenyCmd_Registered(t *testing.T) {
	t.Parallel()
	root := cli.NewRootCommand()
	cmd, _, err := root.Find([]string{"deny"})
	require.NoError(t, err)
	assert.Equal(t, "deny", cmd.Name())
}

// TestApproveCmd_RegisteredWithoutExperimental verifies approve works without KEYLATCH_EXPERIMENTAL.
func TestApproveCmd_RegisteredWithoutExperimental(t *testing.T) {
	t.Setenv("KEYLATCH_EXPERIMENTAL", "")
	root := cli.NewRootCommand()
	cmd, _, err := root.Find([]string{"approve"})
	require.NoError(t, err)
	// Epic 23: approve is unconditionally registered — not behind experimental gate.
	assert.Equal(t, "approve", cmd.Name())
}

// TestDenyCmd_RegisteredWithoutExperimental verifies deny works without KEYLATCH_EXPERIMENTAL.
func TestDenyCmd_RegisteredWithoutExperimental(t *testing.T) {
	t.Setenv("KEYLATCH_EXPERIMENTAL", "")
	root := cli.NewRootCommand()
	cmd, _, err := root.Find([]string{"deny"})
	require.NoError(t, err)
	// Epic 23: deny is unconditionally registered — not behind experimental gate.
	assert.Equal(t, "deny", cmd.Name())
}

func TestRecipesCmd_Output(t *testing.T) {
	t.Parallel()
	root := cli.NewRootCommand()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"recipes"})
	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "coming soon")
}
