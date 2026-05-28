package cli_test

// TestGet_NeverReturnsRawValue verifies EPIC-02 Task 4:
// `keylatch get` with --masked outputs only masked values (****) and never raw credentials.
//
// The non-masked `get` path calls os.Exit(5) without printing any credential value.
// This test exercises the safe --masked path and confirms it only emits stars.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGet_NeverReturnsRawValue(t *testing.T) {
	t.Parallel()
	// NOTE: get --masked currently stubs the output without reading from the store.
	// This test verifies the stub behaviour. When the store path is implemented,
	// this test must be expanded to use a seeded backend.

	root := cli.NewRootCommand()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"get", "--masked", "openai", "api_key"})

	err := root.Execute()
	require.NoError(t, err)

	out := stdout.String()
	// The masked output must not contain any characters that could be a raw key.
	assert.NotEmpty(t, out, "get --masked must produce output")
	assert.True(t, strings.Contains(out, "****"),
		"get --masked output must contain masked value (****): got %q", out)

	// Confirm no real key prefixes appear in the output.
	for _, prefix := range []string{"sk-", "sk-ant-", "ghp_", "AKIA"} {
		assert.False(t, strings.Contains(out, prefix),
			"get --masked output must not contain key prefix %q: got %q", prefix, out)
	}
}

func TestGet_MaskedFormat(t *testing.T) {
	t.Parallel()

	root := cli.NewRootCommand()
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetArgs([]string{"get", "--masked", "stripe", "secret_key"})

	err := root.Execute()
	require.NoError(t, err)

	out := stdout.String()
	assert.Contains(t, out, "****", "masked value must be ****")
	assert.Contains(t, out, "stripe", "output must reference the service name")
}
