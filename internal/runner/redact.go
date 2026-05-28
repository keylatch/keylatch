package runner

import (
	"regexp"
)

// redactionPattern pairs a human-readable name with a compiled regex.
// Patterns are compiled once at package init and reused for all Redact calls.
type redactionPattern struct {
	name string
	re   *regexp.Regexp
}

// redactionPatterns is the ordered table of credential-shaped patterns to redact.
// Each match is replaced with [REDACTED:<name>].
// Patterns are ordered from most-specific to least-specific so that overlapping
// patterns (e.g. bearer-token ⊃ openai-key) do not interfere.
var redactionPatterns []redactionPattern

func init() {
	// Compile all patterns at startup to catch regex errors early.
	// Order: specific key prefixes first, then generic bearer/JWT.
	defs := []struct {
		name    string
		pattern string
	}{
		{
			// Anthropic API keys: sk-ant-<base62-ish>
			name:    "anthropic-key",
			pattern: `sk-ant-[A-Za-z0-9_\-]{20,}`,
		},
		{
			// Stripe keys: sk_live_<id> or sk_test_<id>
			name:    "stripe-key",
			pattern: `sk_(live|test)_[A-Za-z0-9]{20,}`,
		},
		{
			// OpenAI API keys: sk-<base62>
			// Must come after anthropic-key to avoid partial matches on sk-ant-...
			name:    "openai-key",
			pattern: `sk-[A-Za-z0-9]{20,}`,
		},
		{
			// JSON Web Tokens: three base64url segments separated by dots.
			name:    "jwt",
			pattern: `ey[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+`,
		},
		{
			// Generic Bearer tokens in Authorization header values.
			// Must come last — broadest pattern.
			name:    "bearer-token",
			pattern: `Bearer [A-Za-z0-9\-._~+/]+=*`,
		},
	}

	for _, d := range defs {
		// Panic at startup rather than silently failing to redact.
		re := regexp.MustCompile(d.pattern)
		redactionPatterns = append(redactionPatterns, redactionPattern{name: d.name, re: re})
	}
}

// Redact replaces credential-shaped strings in body with [REDACTED:<pattern-name>].
// It operates on raw bytes; Go's regexp engine is byte-safe for valid UTF-8 input
// and handles arbitrary byte slices without interpreting rune boundaries.
// Binary-safe: non-UTF-8 bytes that do not match any pattern are passed through unchanged.
func Redact(body []byte) []byte {
	for _, p := range redactionPatterns {
		replacement := []byte("[REDACTED:" + p.name + "]")
		body = p.re.ReplaceAll(body, replacement)
	}
	return body
}
