package cli_test

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// runScaffoldSubcmd runs `registry scaffold <args...>` and returns stdout.
func runScaffoldSubcmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := cli.NewRootCommand()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(append([]string{"registry", "scaffold"}, args...))
	err := root.ExecuteContext(context.Background())
	return buf.String(), err
}

// TestRegistryScaffold_BasicGeneration verifies that `registry scaffold slack-test`
// produces a valid YAML file with expected content in the output directory.
func TestRegistryScaffold_BasicGeneration(t *testing.T) {
	registryTestSetup(t)

	// Use a temp dir to avoid polluting the working tree.
	tmpDir := t.TempDir()

	out, err := runScaffoldSubcmd(t,
		"slack-test",
		"--category", "communication",
		"--field", "bot_token:SLACK_BOT_TOKEN:bearer_token",
		"--out-dir", tmpDir,
	)
	require.NoError(t, err, "scaffold must succeed; output: %s", out)

	// Output file must exist at the expected path.
	outPath := filepath.Join(tmpDir, "slack-test.yaml")
	_, err = os.Stat(outPath)
	require.NoError(t, err, "output file %q must exist", outPath)

	// File must be valid YAML.
	data, err := os.ReadFile(outPath)
	require.NoError(t, err)

	var parsed map[string]interface{}
	err = yaml.Unmarshal(data, &parsed)
	require.NoError(t, err, "generated file must be valid YAML")

	// Provider slug must match.
	assert.Equal(t, "slack-test", parsed["provider"], "provider slug must be slack-test")

	// Category must be set.
	assert.Equal(t, "communication", parsed["category"], "category must be communication")

	// secret_fields must contain bot_token.
	secretFields, ok := parsed["secret_fields"]
	require.True(t, ok, "secret_fields must be present")

	fields, ok := secretFields.([]interface{})
	require.True(t, ok, "secret_fields must be a list")

	found := false
	for _, sf := range fields {
		m, ok := sf.(map[string]interface{})
		if !ok {
			continue
		}
		if m["name"] == "bot_token" {
			found = true
			assert.Equal(t, "SLACK_BOT_TOKEN", m["env_var"], "env_var for bot_token must be SLACK_BOT_TOKEN")
			assert.Equal(t, "bearer_token", m["secret_kind"], "secret_kind for bot_token must be bearer_token")
		}
	}
	assert.True(t, found, "bot_token must appear in secret_fields")
}

// TestRegistryScaffold_OutputMessage verifies that the scaffold command prints the path.
func TestRegistryScaffold_OutputMessage(t *testing.T) {
	registryTestSetup(t)

	tmpDir := t.TempDir()
	out, err := runScaffoldSubcmd(t,
		"my-provider",
		"--category", "automation",
		"--out-dir", tmpDir,
	)
	require.NoError(t, err)
	assert.Contains(t, out, "scaffold: wrote", "scaffold must report the output file path")
	assert.Contains(t, out, "my-provider.yaml", "scaffold output must mention the file name")
}

// TestRegistryScaffold_MissingCategory verifies that missing --category fails.
func TestRegistryScaffold_MissingCategory(t *testing.T) {
	registryTestSetup(t)

	_, err := runScaffoldSubcmd(t, "some-provider")
	assert.Error(t, err, "scaffold without --category must fail")
}

// TestScaffoldCmd_PathTraversalRejected verifies that a path-traversal slug is
// rejected before any file is created.
func TestScaffoldCmd_PathTraversalRejected(t *testing.T) {
	registryTestSetup(t)

	tmpDir := t.TempDir()

	_, err := runScaffoldSubcmd(t,
		"../../../tmp/evil",
		"--category", "automation",
		"--out-dir", tmpDir,
	)
	assert.Error(t, err, "scaffold with path-traversal slug must return an error")

	// Confirm no file was created inside the temp dir or at the traversal target.
	entries, readErr := os.ReadDir(tmpDir)
	require.NoError(t, readErr)
	assert.Empty(t, entries, "no file must be created when slug is rejected")
}

// TestNoTemplateContainsTODOInCoreOrSaaS_CLIPackage confirms that after scaffolding
// (which places TODOs in experimental/), the core/ and saas/ directories remain
// free of TODO markers. This complements the registry-level governance test.
func TestNoTemplateContainsTODOInCoreOrSaaS_CLIPackage(t *testing.T) {
	// Root of the templates/providers directory relative to the module root.
	// Test runs from internal/cli/, so walk up two levels.
	providersRoot := filepath.Join("..", "..", "templates", "providers")

	roots := []string{
		filepath.Join(providersRoot, "core"),
		filepath.Join(providersRoot, "saas"),
	}

	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			require.NoError(t, err)
		}
		if !info.IsDir() {
			continue
		}

		err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
				return nil
			}

			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}

			if bytes.Contains(data, []byte("TODO")) {
				t.Errorf("template %q in %s contains TODO; experimental/ is the only allowed location for TODOs", p, root)
			}
			return nil
		})
		require.NoError(t, err, "WalkDir over %q must not fail", root)
	}
}
