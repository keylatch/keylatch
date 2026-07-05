package runner

//go:generate go run gen_redaction_patterns.go

import (
	"regexp"
)

// redactionPattern pairs a human-readable name with a compiled regex.
// Patterns are compiled once at package init and reused for all Redact calls.
type redactionPattern struct {
	name string
	re   *regexp.Regexp
}

// redactionDef is the single source of truth for a credential-shaped pattern:
// both the full regex used by Redact() at runtime, and the literal substring
// prefix usable by lightweight, regex-free scanners.
//
// docker-server-security hardening (L3): packaging/redaction-patterns.json
// (consumed by packaging/ci/scan-no-secret-in-storage.sh, a bash script that
// only does `grep -F` literal substring matching — it has no regex engine
// dependency) used to be maintained by hand and had drifted from this table
// (missing Stripe/JWT/Bearer; this table was missing GitHub/AWS/Slack).
// redactionDefs is now the ONE source of truth for both: run
// `go generate ./internal/runner` (see gen_redaction_patterns.go) to
// regenerate packaging/redaction-patterns.json from RedactionPrefixes().
// TestRedactionPatternsJSON_MatchesGoTable (redact_test.go) fails the build
// if the two drift again.
type redactionDef struct {
	name    string
	pattern string
	// prefix MUST be a true literal prefix of every string `pattern` can
	// match — it is what packaging/redaction-patterns.json actually contains.
	prefix string
}

// redactionDefs is the ordered table of credential-shaped patterns to redact.
// Each match is replaced with [REDACTED:<name>].
// Patterns are ordered from most-specific to least-specific so that overlapping
// patterns (e.g. bearer-token ⊃ openai-key) do not interfere.
var redactionDefs = []redactionDef{
	{
		// Anthropic API keys: sk-ant-<base62-ish>
		name:    "anthropic-key",
		pattern: `sk-ant-[A-Za-z0-9_\-]{20,}`,
		prefix:  "sk-ant-",
	},
	{
		// Stripe keys: sk_live_<id> or sk_test_<id>
		name:    "stripe-key",
		pattern: `sk_(live|test)_[A-Za-z0-9]{20,}`,
		prefix:  "sk_",
	},
	{
		// OpenAI API keys: sk-<base62>
		// Must come after anthropic-key to avoid partial matches on sk-ant-...
		name:    "openai-key",
		pattern: `sk-[A-Za-z0-9]{20,}`,
		prefix:  "sk-",
	},
	{
		// GitHub classic personal access tokens.
		name:    "github-pat-classic",
		pattern: `ghp_[A-Za-z0-9]{36,}`,
		prefix:  "ghp_",
	},
	{
		// GitHub fine-grained personal access tokens.
		name:    "github-pat-fine-grained",
		pattern: `github_pat_[A-Za-z0-9_]{20,}`,
		prefix:  "github_pat_",
	},
	{
		// AWS access key IDs.
		name:    "aws-access-key",
		pattern: `AKIA[0-9A-Z]{16}`,
		prefix:  "AKIA",
	},
	{
		// Slack bot tokens.
		name:    "slack-bot-token",
		pattern: `xoxb-[A-Za-z0-9\-]+`,
		prefix:  "xoxb-",
	},
	{
		// Slack user tokens.
		name:    "slack-user-token",
		pattern: `xoxp-[A-Za-z0-9\-]+`,
		prefix:  "xoxp-",
	},
	{
		// JSON Web Tokens: three base64url segments separated by dots.
		// "eyJ" (not just "ey") is the practical literal prefix: JWT headers
		// are JSON objects starting with '{' (0x7B), whose base64url encoding
		// conventionally begins "eyJ" — using bare "ey" would be far too
		// noisy for a substring-only scan.
		name:    "jwt",
		pattern: `ey[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+`,
		prefix:  "eyJ",
	},
	{
		// Generic Bearer tokens in Authorization header values.
		// Must come last — broadest pattern.
		name:    "bearer-token",
		pattern: `Bearer [A-Za-z0-9\-._~+/]+=*`,
		prefix:  "Bearer ",
	},
}

// redactionPatterns holds the compiled regexes derived from redactionDefs,
// built once at package init.
var redactionPatterns []redactionPattern

func init() {
	// Compile all patterns at startup to catch regex errors early.
	for _, d := range redactionDefs {
		// Panic at startup rather than silently failing to redact.
		re := regexp.MustCompile(d.pattern)
		redactionPatterns = append(redactionPatterns, redactionPattern{name: d.name, re: re})
	}
}

// RedactionPrefixes returns the literal, deduplicated, order-stable list of
// prefixes derived from redactionDefs — the same list
// packaging/redaction-patterns.json must contain (see gen_redaction_patterns.go
// and TestRedactionPatternsJSON_MatchesGoTable in redact_test.go).
func RedactionPrefixes() []string {
	seen := make(map[string]bool, len(redactionDefs))
	out := make([]string, 0, len(redactionDefs))
	for _, d := range redactionDefs {
		if d.prefix == "" || seen[d.prefix] {
			continue
		}
		seen[d.prefix] = true
		out = append(out, d.prefix)
	}
	return out
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
