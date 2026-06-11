package cli

// cov_b_policy_pure_test.go — Agent B coverage for pure helper functions in
// policy_cmd.go: newRuleID, pathDir.
// Hermetic: no network, no OS keychain, no filesystem writes.

import (
	"strings"
	"testing"
)

// --- newRuleID ---

func TestNewRuleID_Format(t *testing.T) {
	id, err := newRuleID()
	if err != nil {
		t.Fatalf("newRuleID: %v", err)
	}

	// Should be a UUID v4-like string: 8-4-4-4-12 hex chars.
	parts := strings.Split(id, "-")
	if len(parts) != 5 {
		t.Errorf("expected 5 parts separated by '-', got %d: %s", len(parts), id)
	}
	expected := []int{8, 4, 4, 4, 12}
	for i, part := range parts {
		if len(part) != expected[i] {
			t.Errorf("part[%d] expected length %d, got %d: %s", i, expected[i], len(part), part)
		}
	}
}

func TestNewRuleID_Unique(t *testing.T) {
	ids := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		id, err := newRuleID()
		if err != nil {
			t.Fatalf("newRuleID[%d]: %v", i, err)
		}
		if _, dup := ids[id]; dup {
			t.Errorf("duplicate rule ID generated at iteration %d: %s", i, id)
		}
		ids[id] = struct{}{}
	}
}

func TestNewRuleID_Version4Variant(t *testing.T) {
	// UUID v4: version nibble is '4', variant bits start with '8', '9', 'a', or 'b'.
	id, err := newRuleID()
	if err != nil {
		t.Fatalf("newRuleID: %v", err)
	}
	parts := strings.Split(id, "-")
	if len(parts) < 3 {
		t.Fatalf("invalid UUID format: %s", id)
	}
	// Third group (parts[2]) starts with the version nibble.
	if len(parts[2]) > 0 && parts[2][0] != '4' {
		t.Errorf("expected version nibble '4' in third UUID group, got: %c in %s", parts[2][0], id)
	}
}

// --- pathDir ---

func TestPathDir_WithSlash(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"default/ai/openrouter/api_key", "default/ai/openrouter"},
		{"a/b", "a"},
		{"default/item", "default"},
	}
	for _, c := range cases {
		got := pathDir(c.input)
		if got != c.expected {
			t.Errorf("pathDir(%q) = %q, want %q", c.input, got, c.expected)
		}
	}
}

func TestPathDir_NoSlash(t *testing.T) {
	got := pathDir("rootlevel")
	if got != "." {
		t.Errorf("pathDir('rootlevel') = %q, want '.'", got)
	}
}

func TestPathDir_Empty(t *testing.T) {
	got := pathDir("")
	if got != "." {
		t.Errorf("pathDir('') = %q, want '.'", got)
	}
}

func TestPathDir_TrailingSlash(t *testing.T) {
	// Last index of '/' is the trailing one.
	got := pathDir("default/ai/openrouter/")
	if got != "default/ai/openrouter" {
		t.Errorf("pathDir('default/ai/openrouter/') = %q, want 'default/ai/openrouter'", got)
	}
}
