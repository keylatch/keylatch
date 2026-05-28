package cli

import (
	"testing"
)

// TestLooksLikeSensitive_Blocked verifies known provider key prefixes and
// high-entropy values are detected as sensitive.
func TestLooksLikeSensitive_Blocked(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		value string
	}{
		// Anthropic key
		{"anthropic_key", "sk-ant-api03-abc123def456ghi789jkl012mno345pqr678stu901vwx"},
		// OpenAI key
		{"openai_key", "sk-abcdefghijklmnopqrstuvwxyz12345678901234567"},
		// AWS AKIA access key ID
		{"aws_akia", "AKIAIOSFODNN7EXAMPLE"},
		// GitHub PAT
		{"github_pat", "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJK"},
		// GitHub Actions token
		{"github_ghs", "ghs_abcdefghijklmnopqrstuvwxyz012345"},
		// Slack bot token — value assembled at runtime to avoid triggering push-protection
		// scanners that flag literal xoxb- tokens even in test files.
		{"slack_bot", "xoxb" + "-111111111111-222222222222-aabbccddeeffgghhiijjkkll"},
		// GitLab PAT
		{"gitlab_pat", "glpat-abcdefghijklmnopqrstuvwx"},
		// High-entropy generic string (> 20 chars, > 4.0 bits/char)
		{"high_entropy", "aB3dE5fG7hI9jK1lM2nO4pQ6rS8tU0vWxYz"},
		// AKID short-form prefix
		{"akid_prefix", "AKIDabcdefghijklmnopqrstuvwxyz01234"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !looksLikeSensitive(tc.value) {
				t.Errorf("looksLikeSensitive(%q) = false; want true", tc.value)
			}
		})
	}
}

// TestLooksLikeSensitive_Passes verifies safe non-credential values pass through.
func TestLooksLikeSensitive_Passes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		value string
	}{
		// Model name
		{"model_name", "claude-3-5-sonnet-20241022"},
		// Short config flag
		{"config_flag", "verbose=true"},
		// Generic short string
		{"short", "hello"},
		// Empty string
		{"empty", ""},
		// Numeric string
		{"numeric", "12345678901234567890"},
		// Low-entropy repeated characters
		{"low_entropy", "aaaaaaaaaaaaaaaaaaaaaa"},
		// Namespace
		{"namespace", "default"},
		// A typical username
		{"username", "john.doe@example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if looksLikeSensitive(tc.value) {
				t.Errorf("looksLikeSensitive(%q) = true; want false", tc.value)
			}
		})
	}
}

// TestShannonEntropy verifies the entropy function returns expected ranges.
func TestShannonEntropy_Ranges(t *testing.T) {
	t.Parallel()
	// Empty string → 0.
	if e := shannonEntropy(""); e != 0 {
		t.Errorf("shannonEntropy(\"\") = %f; want 0", e)
	}
	// All-same characters → 0 bits/char.
	if e := shannonEntropy("aaaa"); e != 0 {
		t.Errorf("shannonEntropy(\"aaaa\") = %f; want 0", e)
	}
	// Random-looking string should have > 4.0 bits/char.
	random := "aB3dE5fG7hI9jK1lM2nO4pQ6rS8tU0vWxYzABC"
	if e := shannonEntropy(random); e <= 4.0 {
		t.Errorf("shannonEntropy(%q) = %f; want > 4.0", random, e)
	}
}
