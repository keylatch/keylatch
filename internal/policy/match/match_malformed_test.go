package match_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/policy/match"
)

func TestMatchers_MalformedPatternNeverMatches(t *testing.T) {
	const bad = "[unterminated"
	if match.MatchActor(bad, "[unterminated") {
		t.Error("MatchActor matched malformed pattern")
	}
	if match.MatchConnection(bad, "[unterminated") {
		t.Error("MatchConnection matched malformed pattern")
	}
	if match.MatchCapability(bad, "[unterminated") {
		t.Error("MatchCapability matched malformed pattern")
	}
	if match.MatchCWD(bad, "[unterminated") {
		t.Error("MatchCWD matched malformed pattern")
	}
	if match.MatchCommand(bad, nil) {
		t.Error("MatchCommand matched malformed pattern with empty argv")
	}
	if match.MatchCommand(bad, []string{"[unterminated"}) {
		t.Error("MatchCommand matched malformed pattern")
	}
}

func TestMatchers_EmptyPatternDenies(t *testing.T) {
	if match.MatchConnection("", "") || match.MatchCapability("", "") || match.MatchCWD("", "") || match.MatchActor("", "") {
		t.Fatal("empty pattern must not match")
	}
}

func TestMatchCommand_Boundaries(t *testing.T) {
	cases := []struct {
		pattern string
		argv    []string
		want    bool
	}{
		{"", nil, true},
		{"", []string{"ls"}, false},
		{"*", nil, true},
		{"git push", []string{"git", "push", "origin"}, true},
		{"git push", []string{"git", "pushx"}, false},
		{"git push", []string{"git"}, false},
		{"tsx scripts/*", []string{"tsx", "scripts/a.ts", "x"}, true},
		{"tsx scripts/*", []string{"tsx", "scripts/../../etc/passwd"}, false},
		{"tsx scripts/*", []string{"tsx", "scripts/a/b.ts"}, false},
	}
	for _, tc := range cases {
		if got := match.MatchCommand(tc.pattern, tc.argv); got != tc.want {
			t.Errorf("MatchCommand(%q, %q) = %v, want %v", tc.pattern, tc.argv, got, tc.want)
		}
	}
}

func TestMatchCWD_GlobDoesNotCrossSeparators(t *testing.T) {
	if !match.MatchCWD("/home/*/proj", "/home/alice/proj") {
		t.Fatal("expected single-segment glob match")
	}
	if match.MatchCWD("/home/*/proj", "/home/alice/x/proj") {
		t.Fatal("glob crossed path separator")
	}
}
