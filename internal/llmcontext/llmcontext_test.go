package llmcontext_test

import (
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func lookup(env map[string]string) llmcontext.Lookup {
	return func(k string) string { return env[k] }
}

func TestIsLLMSession_TruthTable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		env      map[string]string
		expected bool
	}{
		// Truth-table cases covering the original three signals and their combinations
		{"none set", map[string]string{}, false},
		{"CLAUDE_CODE only", map[string]string{"CLAUDE_CODE": "1"}, true},
		{"CODEX_ENV only", map[string]string{"CODEX_ENV": "1"}, true},
		{"CREDENTIALS_LLM_SESSION=1 only", map[string]string{"CREDENTIALS_LLM_SESSION": "1"}, true},
		{"CLAUDE_CODE + CODEX_ENV", map[string]string{"CLAUDE_CODE": "1", "CODEX_ENV": "yes"}, true},
		{"CLAUDE_CODE + CREDENTIALS", map[string]string{"CLAUDE_CODE": "1", "CREDENTIALS_LLM_SESSION": "1"}, true},
		{"CODEX_ENV + CREDENTIALS", map[string]string{"CODEX_ENV": "1", "CREDENTIALS_LLM_SESSION": "1"}, true},
		{"all three set", map[string]string{"CLAUDE_CODE": "1", "CODEX_ENV": "1", "CREDENTIALS_LLM_SESSION": "1"}, true},

		// CREDENTIALS_LLM_SESSION: "0" disables the generic manual flag; named values trigger.
		{"CREDENTIALS_LLM_SESSION=0", map[string]string{"CREDENTIALS_LLM_SESSION": "0"}, false},
		{"CREDENTIALS_LLM_SESSION=true", map[string]string{"CREDENTIALS_LLM_SESSION": "true"}, true},
		{"CREDENTIALS_LLM_SESSION=empty", map[string]string{"CREDENTIALS_LLM_SESSION": ""}, false},
		{"CREDENTIALS_LLM_SESSION=yes", map[string]string{"CREDENTIALS_LLM_SESSION": "yes"}, true},
		{"CREDENTIALS_LLM_SESSION=windsurf", map[string]string{"CREDENTIALS_LLM_SESSION": "windsurf"}, true},
		{"CREDENTIALS_LLM_SESSION=antigravity", map[string]string{"CREDENTIALS_LLM_SESSION": "antigravity"}, true},

		// CLAUDE_CODE and CODEX_ENV: any non-empty value triggers
		{"CLAUDE_CODE=0", map[string]string{"CLAUDE_CODE": "0"}, true},
		{"CLAUDE_CODE=false", map[string]string{"CLAUDE_CODE": "false"}, true},
		{"CODEX_ENV=0", map[string]string{"CODEX_ENV": "0"}, true},

		// New signals: CURSOR_SESSION, AIDER_SESSION, GEMINI_SESSION, OPENCODE_SESSION
		{"CURSOR_SESSION non-empty", map[string]string{"CURSOR_SESSION": "1"}, true},
		{"CURSOR_SESSION empty", map[string]string{"CURSOR_SESSION": ""}, false},
		{"AIDER_SESSION non-empty", map[string]string{"AIDER_SESSION": "1"}, true},
		{"AIDER_SESSION empty", map[string]string{"AIDER_SESSION": ""}, false},
		{"GEMINI_SESSION non-empty", map[string]string{"GEMINI_SESSION": "1"}, true},
		{"GEMINI_SESSION empty", map[string]string{"GEMINI_SESSION": ""}, false},
		{"OPENCODE_SESSION non-empty", map[string]string{"OPENCODE_SESSION": "1"}, true},
		{"OPENCODE_SESSION empty", map[string]string{"OPENCODE_SESSION": ""}, false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := llmcontext.IsLLMSession(lookup(tc.env))
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestIsLLMSession_Deterministic(t *testing.T) {
	t.Parallel()
	env := map[string]string{"CLAUDE_CODE": "1"}
	l := lookup(env)
	first := llmcontext.IsLLMSession(l)
	second := llmcontext.IsLLMSession(l)
	assert.Equal(t, first, second, "IsLLMSession must be deterministic")
}

func TestReasons_Labels(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		env      map[string]string
		expected []string
	}{
		{"none", map[string]string{}, []string{}},
		{"CLAUDE_CODE only", map[string]string{"CLAUDE_CODE": "1"}, []string{"CLAUDE_CODE"}},
		{"CODEX_ENV only", map[string]string{"CODEX_ENV": "1"}, []string{"CODEX_ENV"}},
		{"CREDENTIALS_LLM_SESSION=1", map[string]string{"CREDENTIALS_LLM_SESSION": "1"}, []string{"CREDENTIALS_LLM_SESSION"}},
		{"CURSOR_SESSION only", map[string]string{"CURSOR_SESSION": "1"}, []string{"CURSOR_SESSION"}},
		{"AIDER_SESSION only", map[string]string{"AIDER_SESSION": "1"}, []string{"AIDER_SESSION"}},
		{"GEMINI_SESSION only", map[string]string{"GEMINI_SESSION": "1"}, []string{"GEMINI_SESSION"}},
		{"OPENCODE_SESSION only", map[string]string{"OPENCODE_SESSION": "1"}, []string{"OPENCODE_SESSION"}},
		{"CLAUDECODE only", map[string]string{"CLAUDECODE": "1"}, []string{"CLAUDECODE"}},
		{"real Claude Code shell", map[string]string{"CLAUDECODE": "1", "CLAUDE_CODE_ENTRYPOINT": "cli"},
			[]string{"CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"}},
		{"manual flag with legacy aliases", map[string]string{"CLAUDE_CODE": "1", "CODEX_ENV": "1", "CREDENTIALS_LLM_SESSION": "1"},
			[]string{"CLAUDE_CODE", "CODEX_ENV", "CREDENTIALS_LLM_SESSION"}},
		{"manual agent label", map[string]string{"KEYLATCH_AGENT_SESSION": "1"}, []string{"KEYLATCH_AGENT_SESSION"}},
		{"manual agent label off", map[string]string{"KEYLATCH_AGENT_SESSION": "0"}, []string{}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := llmcontext.Reasons(lookup(tc.env))
			require.NotNil(t, got, "Reasons must return non-nil slice")
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestReasons_OrderStable(t *testing.T) {
	t.Parallel()
	env := map[string]string{}
	want := make([]string, 0, len(llmcontext.Signals))
	for _, sig := range llmcontext.Signals {
		env[sig.EnvKey] = "1"
		want = append(want, sig.Label)
	}
	assert.Equal(t, want, llmcontext.Reasons(lookup(env)))
}

// Each harness name is checked against what the harness really exports to
// the shell tools it spawns; empty values must not count.
func TestIsLLMSession_HarnessEnvNames(t *testing.T) {
	t.Parallel()
	names := []string{
		"CLAUDECODE",
		"CLAUDE_CODE_ENTRYPOINT",
		"CODEX_SANDBOX",
		"CODEX_SANDBOX_NETWORK_DISABLED",
		"CURSOR_AGENT",
		"CURSOR_TRACE_ID",
		"GEMINI_CLI",
		"OPENCODE",
		"CLAUDE_CODE",
		"CODEX_ENV",
		"CURSOR_SESSION",
		"AIDER_SESSION",
		"GEMINI_SESSION",
		"OPENCODE_SESSION",
	}
	for _, name := range names {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.True(t, llmcontext.IsLLMSession(lookup(map[string]string{name: "1"})), "%s=1 must be detected", name)
			assert.Equal(t, []string{name}, llmcontext.Reasons(lookup(map[string]string{name: "1"})))
			assert.True(t, llmcontext.Classify(lookup(map[string]string{name: "seatbelt"})).Detected())
			assert.False(t, llmcontext.IsLLMSession(lookup(map[string]string{name: ""})), "empty %s must not be detected", name)
		})
	}
}

func TestReasons_NoValues(t *testing.T) {
	t.Parallel()
	// Labels must not contain "=" or env var values
	env := map[string]string{"CLAUDE_CODE": "secret-value", "CODEX_ENV": "another-secret"}
	r := llmcontext.Reasons(lookup(env))
	for _, label := range r {
		assert.False(t, strings.Contains(label, "="), "label must not contain '='")
		assert.False(t, strings.Contains(label, "secret-value"), "label must not contain env var value")
		assert.False(t, strings.Contains(label, "another-secret"), "label must not contain env var value")
	}
}

func TestReasons_EmptyIsNotNil(t *testing.T) {
	t.Parallel()
	r := llmcontext.Reasons(lookup(map[string]string{}))
	require.NotNil(t, r)
	assert.Len(t, r, 0)
}

func TestSignals_CanonicalList(t *testing.T) {
	t.Parallel()
	keys := make(map[string]bool)
	for _, sig := range llmcontext.Signals {
		assert.NotEmpty(t, sig.EnvKey)
		assert.NotEmpty(t, sig.Label)
		assert.False(t, keys[sig.EnvKey], "duplicate EnvKey %q in Signals", sig.EnvKey)
		keys[sig.EnvKey] = true
	}
}

// TestLegacyAliases checks that every legacy name is still detected and is
// attributed to the harness it stands for.
func TestLegacyAliases(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"CLAUDE_CODE":      "claude-code",
		"CODEX_ENV":        "codex",
		"CURSOR_SESSION":   "cursor",
		"GEMINI_SESSION":   "gemini-cli",
		"OPENCODE_SESSION": "opencode",
		"AIDER_SESSION":    "aider",
	}
	for name, harnessID := range cases {
		c := llmcontext.Classify(lookup(map[string]string{name: "1"}))
		assert.True(t, c.Detected(), name)
		assert.Equal(t, harnessID, c.Harness, name)
	}
	c := llmcontext.Classify(lookup(map[string]string{"CREDENTIALS_LLM_SESSION": "1"}))
	assert.True(t, c.Detected())
	assert.Empty(t, c.Harness)
}
