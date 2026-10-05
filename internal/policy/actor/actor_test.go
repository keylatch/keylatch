package actor_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/policy/actor"
)

// mockLookup returns a Lookup that resolves keys from the supplied map.
func mockLookup(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestInferPriority(t *testing.T) {
	cases := []struct {
		name     string
		env      map[string]string
		wantName string
		wantSrc  string
	}{
		{
			name:     "explicit KEYLATCH_ACTOR takes priority 1",
			env:      map[string]string{"KEYLATCH_ACTOR": "my-bot", "CLAUDE_CODE": "1"},
			wantName: "my-bot",
			wantSrc:  "env",
		},
		{
			name:     "CLAUDE_CODE priority 2",
			env:      map[string]string{"CLAUDE_CODE": "1"},
			wantName: "claude-code",
			wantSrc:  "infer",
		},
		{
			name:     "CODEX_ENV priority 3",
			env:      map[string]string{"CODEX_ENV": "true"},
			wantName: "codex",
			wantSrc:  "infer",
		},
		{
			name:     "CLAUDECODE from a real Claude Code shell",
			env:      map[string]string{"CLAUDECODE": "1", "CLAUDE_CODE_ENTRYPOINT": "cli"},
			wantName: "claude-code",
			wantSrc:  "infer",
		},
		{
			name:     "CLAUDE_CODE_ENTRYPOINT alone",
			env:      map[string]string{"CLAUDE_CODE_ENTRYPOINT": "sdk-ts"},
			wantName: "claude-code",
			wantSrc:  "infer",
		},
		{
			name:     "CODEX_SANDBOX from the Codex macOS sandbox",
			env:      map[string]string{"CODEX_SANDBOX": "seatbelt"},
			wantName: "codex",
			wantSrc:  "infer",
		},
		{
			name:     "CODEX_SANDBOX_NETWORK_DISABLED from a Codex shell tool call",
			env:      map[string]string{"CODEX_SANDBOX_NETWORK_DISABLED": "1"},
			wantName: "codex",
			wantSrc:  "infer",
		},
		{
			name:     "empty harness values do not count",
			env:      map[string]string{"CLAUDECODE": "", "CODEX_SANDBOX": ""},
			wantName: "unknown-non-tty",
			wantSrc:  "infer",
		},
		{
			name:     "CREDENTIALS_LLM_SESSION=1 priority 4",
			env:      map[string]string{"CREDENTIALS_LLM_SESSION": "1"},
			wantName: "llm-session",
			wantSrc:  "infer",
		},
		{
			name:     "CREDENTIALS_LLM_SESSION=0 does not trigger llm-session",
			env:      map[string]string{"CREDENTIALS_LLM_SESSION": "0"},
			wantName: "unknown-non-tty",
			wantSrc:  "infer",
		},
		{
			name:     "Cursor agent terminal",
			env:      map[string]string{"CURSOR_AGENT": "1"},
			wantName: "cursor",
			wantSrc:  "infer",
		},
		{
			name:     "Gemini CLI",
			env:      map[string]string{"GEMINI_CLI": "1"},
			wantName: "gemini-cli",
			wantSrc:  "infer",
		},
		{
			name:     "OpenCode",
			env:      map[string]string{"OPENCODE": "1"},
			wantName: "opencode",
			wantSrc:  "infer",
		},
		{
			name:     "Aider manual label",
			env:      map[string]string{"AIDER_SESSION": "1"},
			wantName: "aider",
			wantSrc:  "infer",
		},
		{
			name:     "KEYLATCH_AGENT_SESSION manual label",
			env:      map[string]string{"KEYLATCH_AGENT_SESSION": "1"},
			wantName: "llm-session",
			wantSrc:  "infer",
		},
		{
			name:     "fallback to unknown-non-tty when no signals",
			env:      map[string]string{},
			wantName: "unknown-non-tty",
			wantSrc:  "infer",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := actor.Infer(mockLookup(tc.env))
			if a.Name != tc.wantName {
				t.Errorf("Name = %q, want %q", a.Name, tc.wantName)
			}
			if a.Source != tc.wantSrc {
				t.Errorf("Source = %q, want %q", a.Source, tc.wantSrc)
			}
		})
	}
}

func TestInferNeverEmpty(t *testing.T) {
	// Regardless of the env, Infer must never return empty Name.
	empty := mockLookup(map[string]string{})
	a := actor.Infer(empty)
	if a.Name == "" {
		t.Error("Infer returned empty Name — violates ")
	}
}

func TestValidate(t *testing.T) {
	valid := []string{
		"a",
		"claude-code",
		"human-shell",
		"unknown-non-tty",
		"codex",
		"llm-session",
		"a1",
		"a-b-c",
		"abc123",
	}
	for _, name := range valid {
		if err := actor.Validate(name); err != nil {
			t.Errorf("Validate(%q) returned unexpected error: %v", name, err)
		}
	}

	invalid := []string{
		"",
		"-leading-hyphen",
		"UPPERCASE",
		"with space",
		"with.dot",
		"with_underscore",
		"with@symbol",
		// longer than 63 chars
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	for _, name := range invalid {
		if err := actor.Validate(name); err == nil {
			t.Errorf("Validate(%q) expected error, got nil", name)
		}
	}
}
