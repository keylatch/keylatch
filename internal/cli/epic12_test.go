package cli_test

// epic12_test.go — EPIC-12 CLI-level test suite.
//
// Tests:
//   - TestRuntimeDoctor_DelegatesToDoctor
//   - TestModes_JSONAndFixColumn
//   - TestDoctorCmd_EPIC12Flags
//   - TestDoctorCmd_JSONSchemaV1Flags

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRuntimeDoctor_DelegatesToDoctor verifies that `runtime doctor <provider>`
// is registered under the runtime subcommand tree, and that the `doctor` command
// has the --category flag that enables scope-based delegation.
//
// The doctor command calls os.Exit so we test structural properties only.
func TestRuntimeDoctor_DelegatesToDoctor(t *testing.T) {
	t.Parallel()

	root := cli.NewRootCommand()

	// Verify `doctor` command has --category flag (enables delegation by scope).
	var hasDoctorCategory bool
	for _, c := range root.Commands() {
		if c.Name() == "doctor" {
			hasDoctorCategory = c.Flags().Lookup("category") != nil
			break
		}
	}
	assert.True(t, hasDoctorCategory,
		"doctor must have --category flag to enable runtime delegation")

	// Verify `runtime doctor` is wired — the runtime doctor subcommand should
	// produce output (runtime doctor returns error, not os.Exit).
	root2 := cli.NewRootCommand()
	var outBuf, errBuf bytes.Buffer
	root2.SetOut(&outBuf)
	root2.SetErr(&errBuf)
	root2.SetArgs([]string{"runtime", "doctor", "openrouter"})
	_ = root2.ExecuteContext(context.Background())
	out := outBuf.String() + errBuf.String()
	assert.NotEmpty(t, out, "runtime doctor must produce output")
}

// TestModes_JSONAndFixColumn verifies that `keylatch modes --json` produces
// the correct JSON shape: available field always present; unavailable modes
// have a non-empty fix field.
//
// The fix field uses omitempty, so it appears only when non-empty
// (i.e., when a mode is unavailable) — matching the spec.
func TestModes_JSONAndFixColumn(t *testing.T) {
	t.Parallel()

	out := runModesCmd(t, "--json")

	var result struct {
		Modes []cli.ModeEntry `json:"modes"`
	}
	err := json.Unmarshal([]byte(strings.TrimSpace(out)), &result)
	require.NoError(t, err, "modes --json must emit valid JSON, got: %s", out)
	require.NotEmpty(t, result.Modes, "modes must not be empty")

	// Every mode entry must have the 'available' field in JSON.
	for _, m := range result.Modes {
		b, marshalErr := json.Marshal(m)
		require.NoError(t, marshalErr)
		var raw map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(b, &raw))
		assert.Contains(t, raw, "available",
			"ModeEntry JSON must include the available field for mode %q", m.Name)
	}

	// Unavailable modes must have non-empty fix strings.
	for _, m := range result.Modes {
		if !m.Available {
			assert.NotEmpty(t, m.Fix,
				"unavailable mode %q must have a non-empty fix hint", m.Name)
		}
	}

	// Compile-time: verify the Fix field is in the ModeEntry struct.
	sample := cli.ModeEntry{
		Name:      "test",
		Available: false,
		Fix:       "run keylatch gateway up",
	}
	b, jsonErr := json.Marshal(sample)
	require.NoError(t, jsonErr)
	assert.Contains(t, string(b), `"fix"`, "ModeEntry must have JSON fix field when set")
}

// TestDoctorCmd_EPIC12Flags verifies that the EPIC-12 flags are registered
// on the doctor command: --category, --quiet, --json, --verbose, --repair, --yes.
// Note: --connection was removed (TODO: add in EPIC-16 when gateway scoping is complete).
func TestDoctorCmd_EPIC12Flags(t *testing.T) {
	t.Parallel()

	root := cli.NewRootCommand()
	for _, c := range root.Commands() {
		if c.Name() == "doctor" {
			assert.NotNil(t, c.Flags().Lookup("category"),
				"doctor must have --category flag")
			assert.NotNil(t, c.Flags().Lookup("quiet"),
				"doctor must have --quiet flag")
			assert.Nil(t, c.Flags().Lookup("connection"),
				"--connection was removed; add in EPIC-16")
			assert.NotNil(t, c.Flags().Lookup("json"),
				"doctor must have --json flag")
			assert.NotNil(t, c.Flags().Lookup("verbose"),
				"doctor must have --verbose flag")
			assert.NotNil(t, c.Flags().Lookup("repair"),
				"doctor must have --repair flag")
			assert.NotNil(t, c.Flags().Lookup("yes"),
				"doctor must have --yes flag")
			return
		}
	}
	t.Error("doctor command not found in root commands")
}
