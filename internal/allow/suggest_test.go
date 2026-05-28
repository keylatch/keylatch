package allow_test

import (
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/allow"
)

func TestSuggest_EmptyEnv(t *testing.T) {
	// Unset all known vars to ensure clean slate.
	for _, v := range []string{"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN"} {
		os.Unsetenv(v)
	}
	got := allow.Suggest("")
	if len(got) != 0 {
		t.Errorf("expected no suggestions on empty env, got %v", got)
	}
}

func TestSuggest_SingleSignal(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test")
	got := allow.Suggest("")
	found := false
	for _, p := range got {
		if p == "openai" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected openai in suggestions, got %v", got)
	}
}
