package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/doctor"
)

func doctorSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "schemas", "doctor.schema.json"))
	require.NoError(t, err)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	c := jsonschema.NewCompiler()
	require.NoError(t, c.AddResource("doctor.schema.json", bytes.NewReader(raw)))
	s, err := c.Compile("doctor.schema.json")
	require.NoError(t, err)
	return s
}

func TestDoctorJSONSchema(t *testing.T) {
	schema := doctorSchema(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	env := func(k string) string {
		switch k {
		case "KEYLATCH_CONFIG_DIR":
			return filepath.Join(home, ".keylatch")
		case "KEYLATCH_BACKEND":
			return "file"
		case "CLAUDECODE":
			return "1"
		}
		return ""
	}

	for _, verbose := range []bool{true, false} {
		report, err := doctor.Run(context.Background(), doctor.Options{Env: env, Verbose: verbose})
		require.NoError(t, err)
		exit := doctorExitOK
		if !report.OverallOK {
			exit = doctorExitFailure
		} else if report.HasWarnings {
			exit = doctorExitWarnings
		}
		raw, err := json.Marshal(buildDoctorJSONV1(report, exit))
		require.NoError(t, err)

		var doc any
		require.NoError(t, json.Unmarshal(raw, &doc))
		require.NoError(t, schema.Validate(doc), "verbose=%v: %s", verbose, raw)

		var out struct {
			AgentSession struct {
				Detected bool     `json:"detected"`
				Signals  []string `json:"signals"`
				Harness  string   `json:"harness"`
			} `json:"agent_session"`
			Summary struct {
				Fail    int `json:"fail"`
				Skipped int `json:"skipped"`
			} `json:"summary"`
		}
		require.NoError(t, json.Unmarshal(raw, &out))
		assert.True(t, out.AgentSession.Detected)
		assert.Equal(t, "claude-code", out.AgentSession.Harness)
		if verbose {
			assert.Positive(t, out.Summary.Skipped, "an unbootstrapped machine skips the checks that depend on the bootstrap")
		}
	}
}

func TestDoctorSchemaRejectsMissingFields(t *testing.T) {
	schema := doctorSchema(t)
	assert.Error(t, schema.Validate(map[string]any{"_schema": "v1"}))
}
