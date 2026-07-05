package events

// mux_internal_test.go — white-box parity guard for scrub().
//
// docker-server-security hardening (L3): scrub() used to carry its own
// hand-maintained copy of the credential-prefix list (a THIRD copy, alongside
// internal/runner/redact.go's redactionDefs table and
// packaging/redaction-patterns.json, which is itself generated from
// redactionDefs). scrub() now calls runner.RedactionPrefixes() directly
// instead of a local literal, so there is no separate list left to drift —
// this test exists to catch any future regression that reintroduces one
// (e.g. someone "inlining" the list back in for a perceived optimization).

import (
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/runner"
)

// TestScrub_MatchesRunnerRedactionPrefixes asserts that scrub() redacts every
// prefix internal/runner's redactionDefs table considers credential-shaped —
// the single source of truth this package must stay in sync with.
func TestScrub_MatchesRunnerRedactionPrefixes(t *testing.T) {
	prefixes := runner.RedactionPrefixes()
	if len(prefixes) == 0 {
		t.Fatal("runner.RedactionPrefixes() returned no prefixes — test would pass vacuously")
	}

	for _, prefix := range prefixes {
		input := "value=" + prefix + "restofsecret1234567890"
		got := scrub(input)
		if got != "[REDACTED]" {
			t.Errorf("scrub(%q) = %q, want %q — mux.go's scrub is not using runner.RedactionPrefixes() for prefix %q",
				input, got, "[REDACTED]", prefix)
		}
	}
}

// TestScrub_CanaryStillScrubbed guards the compile-time canary value
// independently of the runner-sourced prefixes.
func TestScrub_CanaryStillScrubbed(t *testing.T) {
	const canary = "KEYLATCH_CANARY_PHASE14_DESKTOP_0xDEADBEEF"
	got := scrub("some text containing " + canary + " embedded")
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("scrub() did not redact the canary value: got %q", got)
	}
}

// TestScrub_BenignStringsPassThrough ensures scrub() does not over-redact
// ordinary, non-credential-shaped strings.
func TestScrub_BenignStringsPassThrough(t *testing.T) {
	for _, s := range []string{"", "github", "read:repo", "claude-code", "approval-123"} {
		if got := scrub(s); got != s {
			t.Errorf("scrub(%q) = %q, want unchanged (no credential pattern present)", s, got)
		}
	}
}
