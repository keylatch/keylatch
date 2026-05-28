package cli_test

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registryTestSetup initialises the registry for CLI command tests.
// It is called from each test that needs registry state, because there is no
// TestMain in package cli_test that already does this.
func registryTestSetup(t *testing.T) {
	t.Helper()
	err := registry.InitFromConfig(context.Background(), func(key string) string {
		return os.Getenv(key)
	})
	require.NoError(t, err, "InitFromConfig must succeed")
}

// runRegistrySubcmd runs a `registry <subcmd> [args...]` command via the real
// root cobra command tree and returns the combined stdout output.
func runRegistrySubcmd(t *testing.T, args ...string) string {
	t.Helper()
	root := cli.NewRootCommand()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(append([]string{"registry"}, args...))
	// Execute silences the PersistentPreRunE since registry is already initialised
	// in this test process — the duplicate Register calls are idempotent.
	_ = root.ExecuteContext(context.Background())
	return buf.String()
}

// TestRegistryList_OutputFormat verifies the tabwriter output format of `registry list`.
func TestRegistryList_OutputFormat(t *testing.T) {
	registryTestSetup(t)
	out := runRegistrySubcmd(t, "list")

	// Header must be present.
	assert.Contains(t, out, "SLUG", "list output must include SLUG column")
	assert.Contains(t, out, "NAME", "list output must include NAME column")
	assert.Contains(t, out, "CATEGORY", "list output must include CATEGORY column")

	// At least one embedded provider must appear.
	assert.True(t,
		strings.Contains(out, "openrouter") ||
			strings.Contains(out, "sentry") ||
			strings.Contains(out, "anthropic"),
		"list output must include at least one known provider, got:\n%s", out)
}

// TestRegistryList_CategoryFilter verifies `registry list --category ai` only shows AI providers.
func TestRegistryList_CategoryFilter(t *testing.T) {
	registryTestSetup(t)
	out := runRegistrySubcmd(t, "list", "--category", "ai")

	// AI providers must appear.
	aiProviders := registry.ListByCategory("ai")
	require.NotEmpty(t, aiProviders, "expected at least one AI provider")
	for _, p := range aiProviders {
		assert.Contains(t, out, p.Provider, "AI provider %q must appear in --category ai output", p.Provider)
	}

	// Non-AI providers must NOT appear.
	nonAI := []string{"sentry", "dropbox", "cloudflare", "google_workspace"}
	for _, slug := range nonAI {
		assert.NotContains(t, out, slug, "%q is not AI, should not appear with --category ai", slug)
	}
}

// TestRegistryDescribe_KnownProvider verifies `registry describe openrouter` shows expected fields.
func TestRegistryDescribe_KnownProvider(t *testing.T) {
	registryTestSetup(t)
	out := runRegistrySubcmd(t, "describe", "openrouter")

	assert.Contains(t, out, "openrouter", "describe must include the provider slug")
	assert.Contains(t, out, "OpenRouter", "describe must include the display name")
	assert.Contains(t, out, "ai", "describe must include the category")
	assert.Contains(t, out, "api_key", "describe must include the auth flow or secret field name")
}

// TestRegistryDescribe_NonExistent verifies `registry describe nonexistent` produces an error.
func TestRegistryDescribe_NonExistent(t *testing.T) {
	registryTestSetup(t)
	root := cli.NewRootCommand()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"registry", "describe", "nonexistent-provider-xyz"})
	_ = root.ExecuteContext(context.Background())
	out := buf.String()
	assert.Contains(t, out, "not found", "describe of unknown provider must mention 'not found'")
}

// TestRegistryReload verifies that `registry reload` completes without error and
// leaves the registry in a consistent state with the expected embedded templates.
// This test would have caught the no-op bug where InitFromConfig was idempotent
// and never cleared stale entries before re-registering.
func TestRegistryReload(t *testing.T) {
	// Seed registry with embedded templates.
	err := registry.InitFromConfig(context.Background(), func(key string) string {
		return os.Getenv(key)
	})
	require.NoError(t, err, "initial InitFromConfig must succeed")

	before := registry.List()
	require.NotEmpty(t, before, "registry must contain templates after initial load")

	// Run reload via the CLI command.
	out := runRegistrySubcmd(t, "reload")

	// Reload must report at least one template loaded.
	assert.Contains(t, out, "registry: loaded", "reload output must include loaded count")

	// Registry must still contain the same templates after reload.
	after := registry.List()
	require.NotEmpty(t, after, "registry must contain templates after reload")
	assert.Equal(t, len(before), len(after), "reload must produce same number of templates as initial load")

	// Known embedded providers must still be present after reload.
	for _, slug := range []string{"openrouter", "sentry"} {
		tmpl, err := registry.Get(slug)
		require.NoError(t, err, "provider %q must exist after reload", slug)
		assert.NotEmpty(t, tmpl.DisplayName, "provider %q must have a display name", slug)
	}
}
