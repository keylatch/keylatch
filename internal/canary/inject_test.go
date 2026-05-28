package canary_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/canary"
)

// canaryPattern matches the expected token format: klc-canary-<provider>-<16hex>
var canaryPattern = regexp.MustCompile(`^klc-canary-[a-z0-9_]+-[0-9a-f]{16}$`)

func TestBuildCanary_MatchesPattern(t *testing.T) {
	token, err := canary.BuildCanary("anthropic")
	if err != nil {
		t.Fatalf("BuildCanary: unexpected error: %v", err)
	}
	if !canaryPattern.MatchString(token) {
		t.Fatalf("token %q does not match pattern %s", token, canaryPattern)
	}
}

func TestBuildCanary_ContainsProvider(t *testing.T) {
	token, err := canary.BuildCanary("openai")
	if err != nil {
		t.Fatalf("BuildCanary: unexpected error: %v", err)
	}
	if !strings.Contains(token, "openai") {
		t.Fatalf("token %q does not contain provider name 'openai'", token)
	}
}

func TestBuildCanary_Unique(t *testing.T) {
	t1, err1 := canary.BuildCanary("anthropic")
	t2, err2 := canary.BuildCanary("anthropic")
	if err1 != nil || err2 != nil {
		t.Fatalf("BuildCanary errors: %v, %v", err1, err2)
	}
	if t1 == t2 {
		t.Fatalf("expected unique tokens, got identical: %q", t1)
	}
}

func TestEnvVarName_BasicProvider(t *testing.T) {
	got := canary.EnvVarName("anthropic")
	if got != "KEYLATCH_CANARY_ANTHROPIC" {
		t.Fatalf("expected KEYLATCH_CANARY_ANTHROPIC, got %q", got)
	}
}

func TestEnvVarName_HyphenatedProvider(t *testing.T) {
	got := canary.EnvVarName("open-ai")
	if got != "KEYLATCH_CANARY_OPEN_AI" {
		t.Fatalf("expected KEYLATCH_CANARY_OPEN_AI, got %q", got)
	}
}
