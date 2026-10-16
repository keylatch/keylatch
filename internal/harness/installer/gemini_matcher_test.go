package installer

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Gemini CLI matches hook groups against its own tool names, anchored; the
// guard must see the shell and every file tool.
func TestGeminiMatcherCoversTheShellAndFileTools(t *testing.T) {
	re, err := regexp.Compile("^(?:" + geminiMatcher + ")$")
	require.NoError(t, err)
	for _, tool := range []string{"run_shell_command", "read_file", "read_many_files", "glob", "search_file_content", "grep_search", "list_directory", "write_file", "replace"} {
		assert.True(t, re.MatchString(tool), tool)
	}
	assert.False(t, re.MatchString("Bash"), "Claude Code's tool name is not Gemini's")
}
