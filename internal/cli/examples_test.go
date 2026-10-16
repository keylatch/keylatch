package cli_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/cli"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/manifest"
	"github.com/keylatch/keylatch/internal/policy/connpolicy"
	"github.com/keylatch/keylatch/internal/policy/enforce"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExamplesValidate proves each shipped example config loads under the
// strict config decoder and each example script only uses commands and flags
// that exist.
func TestExamplesValidate(t *testing.T) {
	root := repoRoot(t)

	configs, err := filepath.Glob(filepath.Join(root, "examples", "config", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, configs)
	for _, path := range configs {
		t.Run(filepath.Base(path), func(t *testing.T) {
			_, err := config.Load(path)
			assert.NoError(t, err)
		})
	}

	tree := cli.NewRootCommand()
	scripts, err := filepath.Glob(filepath.Join(root, "examples", "*", "*.sh"))
	require.NoError(t, err)
	top, err := filepath.Glob(filepath.Join(root, "examples", "*.sh"))
	require.NoError(t, err)
	for _, path := range append(scripts, top...) {
		data, err := os.ReadFile(path) //nolint:gosec // G304: repository examples
		require.NoError(t, err)
		for _, line := range strings.Split(strings.ReplaceAll(string(data), "\\\n", " "), "\n") {
			line = strings.TrimSpace(line)
			if i := strings.LastIndex(line, "| keylatch "); i >= 0 {
				line = line[i+2:]
			}
			if strings.HasPrefix(line, "keylatch ") {
				assert.Empty(t, checkCommand(tree, line), "%s: %s", filepath.Base(path), line)
			}
		}
	}
}

// The shipped policy documents parse, and enforcement decides as each document
// describes once they are installed as the connection policy.
func TestExamplePolicyDocumentsDecideThroughEnforce(t *testing.T) {
	docs, err := connpolicy.ReadDir(filepath.Join(repoRoot(t), "examples", "policy.d"), false)
	require.NoError(t, err)
	require.Len(t, docs, 4)

	dir := t.TempDir()
	store := connpolicy.Store{Dir: filepath.Join(dir, "policy.d")}
	require.NoError(t, store.Replace(docs))
	e := enforce.Enforcer{PolicyPath: filepath.Join(dir, "policy.json"), PolicyDir: store.Dir}

	decide := func(connection string, kind callerkind.Kind, runtime, unit string) enforce.Decision {
		return e.Decide(context.Background(), enforce.Request{Connection: connection, Caller: kind, Runtime: runtime, Unit: unit})
	}
	assert.True(t, decide("openrouter", callerkind.Agent, "gateway_typed", "").Allow)
	assert.False(t, decide("openrouter", callerkind.Agent, "direct_brokered", "").Allow, "an agent gets the gateway runtimes only")
	assert.False(t, decide("openrouter", callerkind.Host, "gateway_typed", "").Allow)
	assert.True(t, decide("stripe", callerkind.Human, "", "").Allow)
	assert.False(t, decide("stripe", callerkind.Agent, "gateway_typed", "").Allow)
	assert.True(t, decide("vercel", callerkind.Service, "gateway_typed", "deploy.service").Allow)
	assert.False(t, decide("vercel", callerkind.Service, "gateway_typed", "other.service").Allow)
	assert.False(t, decide("vercel", callerkind.Human, "", "").Allow)
	assert.True(t, decide("anything-else", callerkind.Human, "", "").Allow, "the fallback lets a human use any connection")
	assert.False(t, decide("anything-else", callerkind.Agent, "gateway_typed", "").Allow)
}

// TestReadmeBackendTable keeps the README backend table identical to the
// support manifest.
func TestReadmeBackendTable(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "README.md"))
	require.NoError(t, err)
	readme := string(data)
	m := manifest.Current()
	for _, e := range m.ByCategory(manifest.CategoryManager) {
		row := "| `" + e.ID + "` | " + string(e.Status) + " |"
		assert.Contains(t, readme, row, "README backend table must list %s as %s", e.ID, e.Status)
	}
}
