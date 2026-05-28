package match_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/policy/match"
)

func TestMatchActor(t *testing.T) {
	cases := []struct {
		pattern string
		actual  string
		want    bool
	}{
		{"*", "claude-code", true},
		{"claude-*", "claude-code", true},
		{"claude-*", "codex", false},
		{"human-shell", "human-shell", true},
		{"human-shell", "human-shell-extra", false},
		{"", "anything", false},
		{"*", "", true},
		{"unknown-*", "unknown-non-tty", true},
		{"llm-session", "llm-session", true},
		{"llm-session", "llm-sessionx", false},
	}
	for _, tc := range cases {
		got := match.MatchActor(tc.pattern, tc.actual)
		if got != tc.want {
			t.Errorf("MatchActor(%q, %q) = %v, want %v", tc.pattern, tc.actual, got, tc.want)
		}
	}
}

func TestMatchConnection(t *testing.T) {
	cases := []struct {
		pattern    string
		connection string
		want       bool
	}{
		{"openrouter:*", "openrouter:dev", true},
		{"openrouter:*", "openrouter:prod", true},
		{"openrouter:dev", "openrouter:dev", true},
		{"openrouter:dev", "openrouter:prod", false},
		{"*", "any-connection", true},
		{"", "anything", false},
		{"github:*", "openrouter:dev", false},
	}
	for _, tc := range cases {
		got := match.MatchConnection(tc.pattern, tc.connection)
		if got != tc.want {
			t.Errorf("MatchConnection(%q, %q) = %v, want %v", tc.pattern, tc.connection, got, tc.want)
		}
	}
}

func TestMatchCapability(t *testing.T) {
	cases := []struct {
		pattern string
		cap     string
		want    bool
	}{
		{"openrouter.*", "openrouter.chat.create", true},
		{"openrouter.*", "openrouter.models.list", true},
		{"openrouter.*", "stripe.charge.create", false},
		{"*", "any.capability", true},
		{"inject", "inject", true},
		{"inject", "inject.extra", false},
		{"", "anything", false},
		{"read", "read", true},
		{"read", "reader", false},
		{"*.reveal", "db.credentials.reveal", true},
		{"*.dump", "db.dump", true},
		{"export", "export", true},
	}
	for _, tc := range cases {
		got := match.MatchCapability(tc.pattern, tc.cap)
		if got != tc.want {
			t.Errorf("MatchCapability(%q, %q) = %v, want %v", tc.pattern, tc.cap, got, tc.want)
		}
	}
}

func TestMatchCommand(t *testing.T) {
	cases := []struct {
		pattern string
		argv    []string
		want    bool
	}{
		{"tsx scripts/openrouter/*", []string{"tsx", "scripts/openrouter/foo.ts", "arg"}, true},
		{"tsx scripts/openrouter/*", []string{"tsx", "scripts/other/foo.ts"}, false},
		{"node *", []string{"node", "server.js"}, true},
		{"node server.js", []string{"node", "server.js"}, true},
		{"node server.js", []string{"node", "client.js"}, false},
		{"*", []string{"anything"}, true},
		{"", []string{}, true},
		{"", []string{"cmd"}, false},
		// empty argv with non-empty pattern
		{"node", []string{}, false},
		// unicode paths
		{"tsx /tmp/日本語/*", []string{"tsx", "/tmp/日本語/script.ts"}, true},
	}
	for _, tc := range cases {
		got := match.MatchCommand(tc.pattern, tc.argv)
		if got != tc.want {
			t.Errorf("MatchCommand(%q, %v) = %v, want %v", tc.pattern, tc.argv, got, tc.want)
		}
	}
}

func TestMatchCWD(t *testing.T) {
	cases := []struct {
		pattern string
		cwd     string
		want    bool
	}{
		{"/home/user/projects/*", "/home/user/projects/keylatch", true},
		{"/home/user/projects/*", "/home/user/other", false},
		// "*" in path.Match does not cross "/" boundaries — use a full wildcard
		// like "/*" or a real path prefix to match rooted paths.
		{"/*", "/any", true},
		{"", "/any/path", false},
		{"/tmp/*", "/tmp/work", true},
		{"/tmp/work", "/tmp/work", true},
		{"/tmp/work", "/tmp/work/sub", false},
		// deep wildcard using multiple segments
		{"/home/*/projects/*", "/home/user/projects/keylatch", true},
	}
	for _, tc := range cases {
		got := match.MatchCWD(tc.pattern, tc.cwd)
		if got != tc.want {
			t.Errorf("MatchCWD(%q, %q) = %v, want %v", tc.pattern, tc.cwd, got, tc.want)
		}
	}
}
