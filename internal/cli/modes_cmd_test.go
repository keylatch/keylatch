package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/cli"
)

// runModesCmd executes `keylatch modes [args...]` via the real root command
// and returns stdout as a string.
func runModesCmd(t *testing.T, args ...string) string {
	t.Helper()
	root := cli.NewRootCommand()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(append([]string{"modes"}, args...))
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Logf("ExecuteContext error: %v", err)
	}
	return buf.String()
}

// TestModesCmdTable verifies the tabwriter output of `keylatch modes`.
//
// The table has AVAILABLE and FIX columns and lists only the modes that exist.
func TestModesCmdTable(t *testing.T) {
	out := runModesCmd(t)

	assert.Contains(t, out, "gateway_typed", "table must list gateway_typed mode")
	assert.Contains(t, out, "gateway_sdk", "table must list gateway_sdk mode")
	assert.Contains(t, out, "minted", "table must list minted mode")
	assert.Contains(t, out, "gateway_proxy", "table must list gateway_proxy mode")
	assert.Contains(t, out, "USE WHEN", "table must have USE WHEN header")
	assert.Contains(t, out, "AVAILABLE", "table must have AVAILABLE header")
	assert.Contains(t, out, "FIX", "table must have FIX header")
	assert.NotContains(t, out, "classic", "removed runtimes must not be listed")
}

// TestModesCmdJSON verifies `keylatch modes --json` returns valid JSON
// with exactly the 4 modes that exist.
func TestModesCmdJSON(t *testing.T) {
	out := runModesCmd(t, "--json")

	// Must be valid JSON wrapping a {"modes": [...]} object.
	var result struct {
		Modes []cli.ModeEntry `json:"modes"`
	}
	err := json.Unmarshal([]byte(strings.TrimSpace(out)), &result)
	require.NoError(t, err, "modes --json must emit valid JSON, got: %s", out)

	assert.Len(t, result.Modes, 4, "modes --json must have exactly 4 entries")

	// First entry must be gateway_typed.
	require.NotEmpty(t, result.Modes, "modes must not be empty")
	assert.Equal(t, "gateway_typed", result.Modes[0].Name, "first entry must be gateway_typed")
	assert.NotEmpty(t, result.Modes[0].Requires, "gateway_typed should have a Requires value")

	// Last entry must be gateway_proxy.
	lastMode := result.Modes[len(result.Modes)-1]
	assert.Equal(t, "gateway_proxy", lastMode.Name, "last entry must be gateway_proxy")

	// Every entry must have the Available field.
	for _, m := range result.Modes {
		assert.NotEmpty(t, m.Name, "mode name must not be empty")
		// If unavailable, must provide a Fix hint.
		if !m.Available {
			assert.NotEmpty(t, m.Fix, "unavailable mode %q must provide a fix hint", m.Name)
		}
	}
}
