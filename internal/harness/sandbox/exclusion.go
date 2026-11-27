// Package sandbox recognises Keylatch entries in an agent harness's sandbox
// exclusion list. Doctor reports them and the installer removes them, so the
// rule lives here, in a leaf both can import.
package sandbox

import (
	"path"
	"runtime"
	"sort"
	"strings"
)

// safeVerbs are top-level subcommands that start no child process chosen by
// their arguments. `doctor` runs fixed probes such as `<bin> --version`, which
// the caller cannot redirect. Every other verb is treated as able to run
// arbitrary commands, since `run` and `launch` execute their argv outside the
// sandbox when excluded.
var safeVerbs = map[string]bool{
	"actors": true, "approve": true, "audit": true, "call": true, "check-expiry": true,
	"completion": true, "config": true, "connections": true, "deny": true,
	"describe": true, "doctor": true, "env": true, "grant": true, "health": true,
	"help-topic": true, "list": true, "mint": true, "modes": true, "paths": true,
	"policy": true, "recipes": true, "registry": true, "scope": true, "security": true,
	"status": true, "validate": true, "version": true, "versions": true,
}

// SafeVerbs lists the subcommands the matcher treats as not spawning children.
func SafeVerbs() []string {
	verbs := make([]string, 0, len(safeVerbs))
	for v := range safeVerbs {
		verbs = append(verbs, v)
	}
	sort.Strings(verbs)
	return verbs
}

// MatchKeylatch reports whether an excludedCommands pattern targets the
// keylatch binary, and whether it can cover a child-spawning subcommand.
// Anything that is not a literal known non-spawning verb counts as covering
// one: an empty verb, leading flags, and glob characters.
func MatchKeylatch(pattern string) (matches, coversRun bool) {
	return MatchKeylatchOn(runtime.GOOS, pattern)
}

// MatchKeylatchOn matches the program name case-insensitively on the platforms
// whose filesystems are.
func MatchKeylatchOn(goos, pattern string) (matches, coversRun bool) {
	p := strings.TrimSpace(pattern)
	prog, rest := splitProgram(p)
	prog = strings.TrimSuffix(prog, "*")
	prog = strings.ReplaceAll(prog, `\`, "/")
	base := path.Base(prog)
	if len(base) > 4 && strings.EqualFold(base[len(base)-4:], ".exe") {
		base = base[:len(base)-4]
	}
	if goos == "darwin" || goos == "windows" {
		base = strings.ToLower(base)
	}
	if base != "keylatch" {
		return false, false
	}
	rest = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), ":"))
	verb, _, _ := strings.Cut(strings.Join(strings.Fields(rest), " "), " ")
	verb, _, _ = strings.Cut(verb, ":")
	if verb == "" || strings.HasPrefix(verb, "-") || strings.ContainsAny(verb, "*?[") {
		return true, true
	}
	return true, !safeVerbs[verb]
}

// splitProgram separates the program from the arguments. A leading quoted
// token is the program; otherwise it ends at the first whitespace, and a rule
// separator `:` only counts after the last path separator so drive letters
// are not mistaken for it.
func splitProgram(p string) (prog, rest string) {
	if p != "" && (p[0] == '"' || p[0] == '\'') {
		if end := strings.IndexByte(p[1:], p[0]); end >= 0 {
			return p[1 : 1+end], p[2+end:]
		}
	}
	token, tail := p, ""
	if i := strings.IndexAny(p, " \t"); i >= 0 {
		token, tail = p[:i], p[i:]
	}
	sep := strings.LastIndexAny(token, `/\`)
	if i := strings.IndexByte(token[sep+1:], ':'); i >= 0 {
		i += sep + 1
		return token[:i], token[i+1:] + tail
	}
	return token, tail
}
