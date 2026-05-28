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
// T-09-03: Updated to reflect the new AVAILABLE and FIX columns.
// EPIC-24: direct_classic_sandboxed is now listed (reinstated as a new sibling mode).
// direct_classic remains permanently removed and must not appear.
func TestModesCmdTable(t *testing.T) {
	out := runModesCmd(t)

	assert.Contains(t, out, "gateway_typed", "table must list gateway_typed mode")
	assert.Contains(t, out, "gateway_sdk", "table must list gateway_sdk mode")
	assert.Contains(t, out, "direct_brokered", "table must list direct_brokered mode")
	assert.Contains(t, out, "gateway_proxy", "table must list gateway_proxy mode")
	// EPIC-24: reinstated mode must appear.
	assert.Contains(t, out, "direct_classic_sandboxed", "table must list direct_classic_sandboxed (EPIC-24)")
	assert.Contains(t, out, "USE WHEN", "table must have USE WHEN header")
	assert.Contains(t, out, "AVAILABLE", "table must have AVAILABLE header (T-09-03)")
	assert.Contains(t, out, "FIX", "table must have FIX header (T-09-03)")

	// direct_classic (without _sandboxed suffix) is permanently removed and
	// must not appear as a mode row. The note may mention it.
	// We check for the tab-separated row marker to distinguish from the note.
	assert.NotContains(t, out, "direct_classic\t", "direct_classic row must not appear (permanently removed)")

	// Note about removed modes should still be present.
	assert.Contains(t, out, "direct_classic", "removal note must mention direct_classic")
}

// TestModesCmdJSON verifies `keylatch modes --json` returns valid JSON
// with exactly 5 modes (the EPIC-24 set: original 4 + direct_classic_sandboxed).
func TestModesCmdJSON(t *testing.T) {
	out := runModesCmd(t, "--json")

	// Must be valid JSON wrapping a {"modes": [...]} object.
	var result struct {
		Modes []cli.ModeEntry `json:"modes"`
	}
	err := json.Unmarshal([]byte(strings.TrimSpace(out)), &result)
	require.NoError(t, err, "modes --json must emit valid JSON, got: %s", out)

	// EPIC-24: 5 entries (original 4 + direct_classic_sandboxed).
	assert.Len(t, result.Modes, 5, "modes --json must have exactly 5 entries after EPIC-24")

	// First entry must be gateway_typed.
	require.NotEmpty(t, result.Modes, "modes must not be empty")
	assert.Equal(t, "gateway_typed", result.Modes[0].Name, "first entry must be gateway_typed")
	assert.NotEmpty(t, result.Modes[0].Requires, "gateway_typed should have a Requires value")

	// Last entry must be direct_classic_sandboxed (EPIC-24).
	lastMode := result.Modes[len(result.Modes)-1]
	assert.Equal(t, "direct_classic_sandboxed", lastMode.Name, "last entry must be direct_classic_sandboxed")

	// Every entry must have the Available field (T-09-03).
	for _, m := range result.Modes {
		assert.NotEmpty(t, m.Name, "mode name must not be empty")
		// If unavailable, must provide a Fix hint.
		if !m.Available {
			assert.NotEmpty(t, m.Fix, "unavailable mode %q must provide a fix hint", m.Name)
		}
	}
}
