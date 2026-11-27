package guard

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHookAlreadyInstalled_Shapes(t *testing.T) {
	const script = "/h/.keylatch/hooks/x-guard.sh"
	nested := map[string]any{"hooks": []any{map[string]any{"command": script}}}
	cases := []struct {
		name     string
		settings map[string]any
		want     bool
	}{
		{"no hooks key", map[string]any{}, false},
		{"hooks is a string", map[string]any{"hooks": "x"}, false},
		{"array skips junk then matches", map[string]any{"hooks": []any{1, "s", nested}}, true},
		{"array top-level command", map[string]any{"hooks": []any{map[string]any{"command": script}}}, true},
		{"array other command", map[string]any{"hooks": []any{map[string]any{"command": script + ".bak"}}}, false},
		{"object BeforeTool", map[string]any{"hooks": map[string]any{"BeforeTool": []any{"junk", nested}}}, true},
		{"object other event ignored", map[string]any{"hooks": map[string]any{"PostToolUse": []any{nested}}}, false},
		{"command not a string", map[string]any{"hooks": []any{map[string]any{"command": 5}}}, false},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, hookAlreadyInstalled(tc.settings, script), tc.name)
	}
}

func TestScriptContentAndName(t *testing.T) {
	for _, a := range SupportedAgents {
		if a == AgentAntigravity {
			_, err := scriptContent(a)
			require.Error(t, err)
			continue
		}
		b, err := scriptContent(a)
		require.NoError(t, err, "agent %s", a)
		assert.NotEmpty(t, b)
	}
	assert.Equal(t, "block-keylatch-exfiltration.sh", scriptName(AgentClaudeCode))
	assert.Equal(t, "keylatch-guard.ts", scriptName(AgentOpenCode))
	assert.Equal(t, "codex-guard.sh", scriptName(AgentCodex))
}

func TestWriteGuardScript_UnknownAgent(t *testing.T) {
	_, err := writeGuardScript("nope", InstallOpts{ProjectDir: t.TempDir()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no script for agent")
}

func TestWriteGuardScriptTo_OpenCodeNotExecutable(t *testing.T) {
	dir := t.TempDir()
	p, err := writeGuardScriptTo(AgentOpenCode, []byte("x"), InstallOpts{ProjectDir: dir})
	require.NoError(t, err)
	assert.Contains(t, p, "keylatch-guard.ts")
	gdAssertModeInternal(t, p, 0o600)
}

func TestSplitLinesAndContains(t *testing.T) {
	assert.Nil(t, splitLines(""))
	assert.Equal(t, []string{"a", "b\r", "c"}, splitLines("a\nb\r\nc"))
	assert.Equal(t, []string{"a", ""}, splitLines("a\n\n"))

	assert.True(t, contains("abc", ""))
	assert.True(t, contains("abc", "abc"))
	assert.True(t, contains("xxpre-tool-use-hook: y", "pre-tool-use-hook"))
	assert.False(t, contains("ab", "abc"))
	assert.False(t, contains("abcd", "ce"))
}
