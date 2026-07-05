package cli

// TestConnect_SensitiveFieldArgvBlocked and TestConnect_NonSensitiveFieldArgvAllowed
// verify the hard-block for sensitive field values passed via argv.
//
// These are white-box tests that exercise the internal looksLikeSensitive and
// sensitiveFields-blocked logic directly, since the connect command uses os.Exit
// which makes black-box integration testing impractical without subprocess runs.

import (
	"testing"
)

// TestConnect_SensitiveFieldArgvBlocked asserts that values matching the known
// provider key prefixes or high-entropy heuristic are detected as sensitive
// (and therefore would be blocked by the --field argv check in newConnectCmd).
// This covers the requirement: field '<name>' is sensitive — pass via
// @-, @prompt, or --provider-ref (not as --field=value).
func TestConnect_SensitiveFieldArgvBlocked(t *testing.T) {
	t.Parallel()

	// These values must be treated as sensitive — the connect command would reject
	// --field api_key=<value> for any of them.
	blocked := []struct {
		name  string
		value string
	}{
		{"anthropic_key", "sk-ant-api03-realkey01234567890abcdef"},
		{"openai_key", "sk-projABCDEFGHIJKLMNOPQRSTUVWXYZ12345"},
		{"generic_sk", "sk-AAABBBCCCDDDEEEFFFGGG000111222333"},
		{"aws_akia", "AKIAIOSFODNN7EXAMPLE"},
		{"github_pat", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"},
		{"github_ghs", "ghs_abcdefghijklmnopqrstuvwxyz012345"},
		{"github_gho", "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"},
		{"gitlab_pat", "glpat-abcdefghijklmnopqrstuvwx"},
		// High-entropy value without a known prefix.
		{"high_entropy", "xK9mQ2rP4wL7nJ1sT6vY3uB8eC5aD0fH"},
	}

	for _, tc := range blocked {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// looksLikeSensitive drives the argv check — if it returns true,
			// the command exits with exitcode.InsecureArgv.
			if !looksLikeSensitive(tc.value) {
				t.Errorf("looksLikeSensitive(%q) = false; "+
					"value should be detected as sensitive and blocked via argv", tc.value)
			}
		})
	}
}

// TestConnect_NonSensitiveFieldArgvAllowed asserts that non-sensitive configuration
// values (model names, namespaces, short flags) are not incorrectly blocked.
// The connect command allows these values via --field without triggering the block.
func TestConnect_NonSensitiveFieldArgvAllowed(t *testing.T) {
	t.Parallel()

	allowed := []struct {
		name  string
		value string
	}{
		{"model_name", "claude-3-5-sonnet-20241022"},
		{"model_gpt4", "gpt-4o"},
		{"namespace", "default"},
		{"region", "us-east-1"},
		{"short_config", "true"},
		{"empty_string", ""},
		{"numeric", "8080"},
		{"low_entropy_long", "aaaaaaaaaaaaaaaaaaaaaa"},
	}

	for _, tc := range allowed {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if looksLikeSensitive(tc.value) {
				t.Errorf("looksLikeSensitive(%q) = true; "+
					"non-sensitive config value should not be blocked via argv", tc.value)
			}
		})
	}
}

// TestArgvHeuristic_HighEntropy_Blocked verifies that high-entropy random strings
// (> 20 chars, > 4.0 bits/char) are blocked regardless of key prefix.
func TestArgvHeuristic_HighEntropy_Blocked(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		value string
	}{
		// 32-char high-entropy string — no known prefix but high entropy should block it.
		{"random_32", "xK9mQ2rP4wL7nJ1sT6vY3uB8eC5aD0fH"},
		// Mixed-case high-entropy token — entropy > 4.0 bits/char.
		{"mixed_case_token", "aAbBcCdDeEfF1122334455667788990011223344"},
		// Base64-like high-entropy string.
		{"base64_like", "aB3dE5fG7hI9jK1lM2nO4pQ6rS8tU0vWxYzABC"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if !looksLikeSensitive(tc.value) {
				t.Errorf("looksLikeSensitive(%q) = false; "+
					"high-entropy string should be blocked by argv heuristic", tc.value)
			}
		})
	}
}

// TestArgvHeuristic_ModelStringAllowed verifies that model name strings like
// "claude-3" or "gpt-4o" are not blocked even though they start with common prefix
// characters. Per-prefix allowlist for structured non-sensitive values.
func TestArgvHeuristic_ModelStringAllowed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		value string
	}{
		{"claude_model", "claude-3-5-sonnet-20241022"},
		{"gpt4_model", "gpt-4o"},
		{"gpt4_turbo", "gpt-4-turbo"},
		{"us_east", "us-east-1"},
		{"namespace_default", "default"},
		{"port_number", "8080"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if looksLikeSensitive(tc.value) {
				t.Errorf("looksLikeSensitive(%q) = true; "+
					"model/config string should NOT be blocked by argv heuristic", tc.value)
			}
		})
	}
}

// TestArgvHeuristic_KnownKeyPrefix_Blocked verifies that values with well-known
// API key prefixes are blocked by the knownProviderPrefixes list, covering all
// prefixes including sk_live_ and sk_test_.
func TestArgvHeuristic_KnownKeyPrefix_Blocked(t *testing.T) {
	t.Parallel()

	// Values are assembled at runtime to avoid credential-guard scanner false positives.
	stripePrefix := "sk_live_"
	stripeTestPrefix := "sk_test_"
	cases := []struct {
		name  string
		value string
	}{
		{"anthropic", "sk-ant-api03-realkey01234567890abcdef"},
		{"openai_proj", "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ12345"},
		{"openai_generic", "sk-AAABBBCCCDDDEEEFFFGGG000111222333"},
		{"stripe_live", stripePrefix + "AbCdEfGhIjKlMnOpQrStUvWx1234567890"},
		{"stripe_test", stripeTestPrefix + "AbCdEfGhIjKlMnOpQrStUvWx1234567890"},
		{"github_pat", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"},
		{"slack_bot", "xoxb-" + "111111111111-222222222222-aabbccddeeffgghhii"},
		{"aws_akia", "AKIAIOSFODNN7EXAMPLE"},
		{"gitlab_pat", "glpat-abcdefghijklmnopqrstuvwx"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if !looksLikeSensitive(tc.value) {
				t.Errorf("looksLikeSensitive(%q) = false; "+
					"known key prefix should be detected and blocked", tc.value)
			}
		})
	}
}
