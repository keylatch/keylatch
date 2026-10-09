package explain_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/explain"
	"github.com/keylatch/keylatch/internal/manifest"
	"github.com/keylatch/keylatch/internal/policy"
)

var update = flag.Bool("update", false, "rewrite golden files")

type fixture struct {
	Description        string             `json:"description"`
	Mode               string             `json:"mode"`
	Policy             policy.Policy      `json:"policy"`
	Connection         explain.Connection `json:"connection"`
	UnknownConnections []string           `json:"unknown_connections"`
	EnabledRuntimes    []string           `json:"enabled_runtimes"`
	Request            explain.Request    `json:"request"`
}

func (f fixture) manifest() manifest.Manifest {
	var m manifest.Manifest
	for _, id := range f.EnabledRuntimes {
		m.Entries = append(m.Entries, manifest.Entry{ID: id, Category: manifest.CategoryRuntime, Status: manifest.Supported})
	}
	m.Entries = append(m.Entries,
		manifest.Entry{ID: "gateway_proxy", Category: manifest.CategoryRuntime, Status: manifest.Unavailable, Note: "excluded pending credential-boundary fixes"},
		manifest.Entry{ID: "direct_classic_sandboxed", Category: manifest.CategoryRuntime, Status: manifest.Unavailable, Note: "excluded"},
	)
	return m
}

func (f fixture) run(t *testing.T) any {
	t.Helper()
	m := f.manifest()
	if f.Mode == "policy" {
		unknown := map[string]bool{}
		for _, n := range f.UnknownConnections {
			unknown[n] = true
		}
		return explain.Effective(explain.PolicyInput{
			Policy:   f.Policy,
			Manifest: m,
			Resolve: func(name string) explain.Connection {
				if unknown[name] {
					return explain.Connection{}
				}
				return f.Connection
			},
			Connection: f.Request.Connection,
			Actor:      f.Request.Actor,
		})
	}
	return explain.Run(explain.Input{Policy: f.Policy, Manifest: m, Connection: f.Connection, Request: f.Request})
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	require.NoError(t, enc.Encode(v))
	return buf.Bytes()
}

func compiledSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	require.NoError(t, c.AddResource("explain.json", bytes.NewReader(explain.Schema())))
	s, err := c.Compile("explain.json")
	require.NoError(t, err)
	return s
}

func fixtureFiles(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("testdata/fixtures/*.json")
	require.NoError(t, err)
	return files
}

func TestGolden(t *testing.T) {
	files := fixtureFiles(t)
	require.GreaterOrEqual(t, len(files), 20)
	schema := compiledSchema(t)

	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".json")
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(file)
			require.NoError(t, err)
			var fx fixture
			require.NoError(t, json.Unmarshal(raw, &fx))

			got := marshal(t, fx.run(t))
			golden := filepath.Join("testdata", "golden", name+".json")
			if *update {
				require.NoError(t, os.MkdirAll(filepath.Dir(golden), 0o755))
				require.NoError(t, os.WriteFile(golden, got, 0o644))
			}
			want, err := os.ReadFile(golden)
			require.NoError(t, err, "missing golden; run with -update")
			assert.Equal(t, string(want), string(got))

			var doc any
			require.NoError(t, json.Unmarshal(got, &doc))
			require.NoError(t, schema.Validate(doc))
			assert.Equal(t, string(got), string(marshal(t, fx.run(t))), "output must be deterministic")
		})
	}
}

func TestArgvIsNotEchoed(t *testing.T) {
	fx := fixture{
		Policy:          policy.Policy{Mode: policy.ModeEnforcing},
		Connection:      explain.Connection{Known: true, Runtimes: []string{"gateway_typed"}},
		EnabledRuntimes: []string{"gateway_typed"},
		Request: explain.Request{
			Actor: "human-shell", Connection: "openai",
			Argv: []string{"curl", "-H", "Authorization: Bearer sk-live-secret-value"},
		},
	}
	fx.Policy.DefaultDeny = false
	out := string(marshal(t, fx.run(t)))
	assert.NotContains(t, out, "sk-live-secret-value")
	assert.Contains(t, out, `"executable": "curl"`)
}

func TestSchemaVersionMatches(t *testing.T) {
	var s struct {
		Defs map[string]struct {
			Properties map[string]struct {
				Const any `json:"const"`
			} `json:"properties"`
		} `json:"$defs"`
	}
	require.NoError(t, json.Unmarshal(explain.Schema(), &s))
	assert.EqualValues(t, explain.SchemaVersion, s.Defs["run"].Properties["schema_version"].Const)
	assert.EqualValues(t, explain.SchemaVersion, s.Defs["policy"].Properties["schema_version"].Const)
}

func TestCallerKind(t *testing.T) {
	cases := map[string]string{
		"human-shell": explain.CallerHuman,
		"claude-code": explain.CallerAgent,
		"codex":       explain.CallerAgent,
		"llm-session": explain.CallerAgent,
		"ci-runner":   explain.CallerService,
	}
	for actor, want := range cases {
		assert.Equal(t, want, explain.CallerKind(actor, false), actor)
	}
	assert.Equal(t, explain.CallerAgent, explain.CallerKind("human-shell", true))
}
