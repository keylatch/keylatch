package guard_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/guard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProtectedPaths_DocsAgreeWithScript(t *testing.T) {
	paths := guard.ProtectedPaths()
	require.NotEmpty(t, paths)
	assert.Contains(t, paths, ".kube")
	assert.Contains(t, paths, ".netrc")

	pages, err := filepath.Glob("../../docs/integrations/*.md")
	require.NoError(t, err)
	readmes, err := filepath.Glob("../../contrib/agent-guards/*/README.md")
	require.NoError(t, err)

	for _, page := range append(pages, readmes...) {
		base := filepath.Base(page)
		if base == "aider.md" || base == "opencode.md" || strings.Contains(page, "opencode") || strings.Contains(page, "claude-code") {
			continue
		}
		data, err := os.ReadFile(page)
		require.NoError(t, err)
		for _, p := range paths {
			assert.Contains(t, string(data), "`~/"+p+"`", "%s must list %s", page, p)
		}
	}

	cursor, err := os.ReadFile("../../docs/integrations/cursor.md")
	require.NoError(t, err)
	lines := strings.Split(string(cursor), "\n")
	for _, pattern := range guard.CursorIgnorePatterns() {
		assert.Contains(t, lines, pattern, "cursor.md ignore block must list %s", pattern)
	}
}
