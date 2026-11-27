// Package match provides glob-based matching helpers for the policy engine.
// All matchers use path.Match semantics (forward-slash delimited globs).
// Do NOT use filepath.Match here — capability and actor identifiers use dots
// and slashes, not OS path separators.
package match

import (
	"path"
	"strings"
)

// MatchActor performs glob match (path.Match semantics) of pattern against
// actual actor name. "*" matches any sequence; "claude-*" matches
// "claude-code".
func MatchActor(pattern, actual string) bool {
	if pattern == "" {
		return false
	}
	ok, err := path.Match(pattern, actual)
	if err != nil {
		// Malformed pattern — treat as no-match.
		return false
	}
	return ok
}

// MatchConnection performs glob match on a connection identifier.
// "openrouter:*" matches "openrouter:dev".
func MatchConnection(pattern, connection string) bool {
	if pattern == "" {
		return false
	}
	ok, err := path.Match(pattern, connection)
	if err != nil {
		return false
	}
	return ok
}

// MatchCapability performs glob match on a capability identifier.
// Identifiers are dot-delimited; "openrouter.*" matches
// "openrouter.chat.create".
func MatchCapability(pattern, cap string) bool {
	if pattern == "" {
		return false
	}
	ok, err := path.Match(pattern, cap)
	if err != nil {
		return false
	}
	return ok
}

// MatchCommand performs a glob match against strings.Join(argv, " "). The
// pattern is matched against the full joined string with path.Match, which
// anchors at start and end, so a pattern matches exactly unless it ends in
// "*". There is no implicit trailing wildcard: "pnpm test" does not match
// ["pnpm","test","--","rm"].
//
// "tsx scripts/openrouter/*" matches ["tsx","scripts/openrouter/foo.ts","arg"]
// because the joined string "tsx scripts/openrouter/foo.ts arg" is matched
// with pattern "tsx scripts/openrouter/*".
func MatchCommand(pattern string, argv []string) bool {
	if pattern == "" {
		return len(argv) == 0
	}
	ok, err := path.Match(pattern, strings.Join(argv, " "))
	return err == nil && ok
}

// MatchCWD performs glob match on an absolute working directory path.
func MatchCWD(pattern, cwd string) bool {
	if pattern == "" {
		return false
	}
	ok, err := path.Match(pattern, cwd)
	if err != nil {
		return false
	}
	return ok
}
