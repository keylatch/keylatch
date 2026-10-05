package testutil

import (
	"testing"

	"github.com/keylatch/keylatch/internal/llmcontext"
)

// ClearLLMSessionEnv blanks every LLM session signal for the duration of the
// test, so tests that expect a human session pass when run inside an agent
// harness that exports CLAUDECODE, CODEX_SANDBOX and the like.
func ClearLLMSessionEnv(t testing.TB) {
	t.Helper()
	for _, sig := range llmcontext.Signals {
		t.Setenv(sig.EnvKey, "")
	}
	t.Setenv(llmcontext.TicketEnv, "")
}
