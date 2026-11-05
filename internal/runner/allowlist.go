package runner

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ResolveAllowedCommand checks argv against a template's allowed command
// entries and returns argv with argv[0] replaced by the absolute path of the
// executable that will run.
//
// An entry is an executable name followed by optional argument patterns:
// "node" allows that executable with any arguments, "node script.js" requires
// the first argument to be script.js, "tsx scripts/" lets the first argument
// be any path under scripts/, and "*" matches any one argument. The
// executable matches by exact name, never by prefix: "python3evil" does not
// match "python3". A name given with a path ("/usr/bin/sh") must be argv[0]
// itself. When argv[0] is a path whose name matches, it must be the same file
// the name resolves to on PATH, so a copy planted elsewhere does not pass.
func ResolveAllowedCommand(entries, argv []string) ([]string, bool) {
	if len(argv) == 0 {
		return nil, false
	}
	for _, entry := range entries {
		fields := strings.Fields(entry)
		if len(fields) == 0 || !argsMatch(fields[1:], argv[1:]) {
			continue
		}
		path, ok := resolveExecutable(fields[0], argv[0])
		if !ok {
			continue
		}
		return append([]string{path}, argv[1:]...), true
	}
	return nil, false
}

func argsMatch(patterns, args []string) bool {
	if len(args) < len(patterns) {
		return false
	}
	for i, p := range patterns {
		switch {
		case p == "*":
		case strings.HasSuffix(p, "/"):
			if !strings.HasPrefix(args[i], p) || strings.Contains(args[i], "..") {
				return false
			}
		case args[i] != p:
			return false
		}
	}
	return true
}

func hasPathSeparator(s string) bool { return strings.ContainsAny(s, `/\`) }

func exeName(p string) string {
	name := filepath.Base(p)
	if runtime.GOOS == "windows" {
		name = strings.TrimSuffix(strings.ToLower(name), ".exe")
	}
	return name
}

func resolveExecutable(allowed, argv0 string) (string, bool) {
	if hasPathSeparator(allowed) {
		if argv0 != allowed || !filepath.IsAbs(allowed) {
			return "", false
		}
		return allowed, true
	}
	if exeName(argv0) != exeName(allowed) {
		return "", false
	}
	onPath, err := exec.LookPath(allowed)
	if err != nil || !filepath.IsAbs(onPath) {
		return "", false
	}
	if hasPathSeparator(argv0) && !sameFile(argv0, onPath) {
		return "", false
	}
	return onPath, true
}

func sameFile(a, b string) bool {
	ra, errA := filepath.EvalSymlinks(a)
	rb, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && ra == rb
}
