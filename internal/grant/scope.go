package grant

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// commandSearchPath is where a bare program name in a command scope is
// looked up. The caller's PATH is ignored: whoever controls it would choose
// which binary a grant applies to.
var commandSearchPath = []string{"/usr/local/bin", "/usr/bin", "/bin"}

// parseCommandPattern splits a command scope into arguments and resolves the
// program to an absolute path. A wildcard is only allowed as the last
// argument on its own ("npm test *"), never glued to one ("npm test*").
func parseCommandPattern(pattern string) ([]string, error) {
	argv := strings.Fields(pattern)
	if len(argv) == 0 {
		return nil, errors.New("grant: --command is empty")
	}
	for i, a := range argv {
		if strings.Contains(a, "*") && (a != "*" || i != len(argv)-1 || i == 0) {
			return nil, fmt.Errorf("grant: --command %q: a wildcard must be a separate last argument, as in \"npm test *\"", pattern)
		}
	}
	prog, err := resolveProgram(argv[0])
	if err != nil {
		return nil, err
	}
	argv[0] = prog
	return argv, nil
}

// resolveProgram returns the absolute, symlink-resolved path of name: name
// itself when it is absolute, otherwise the first executable named name in
// commandSearchPath.
func resolveProgram(name string) (string, error) {
	if filepath.IsAbs(name) {
		return realExecutable(name)
	}
	if strings.ContainsAny(name, `/\`) || runtime.GOOS == "windows" {
		return "", fmt.Errorf("grant: program %q must be a bare name or an absolute path", name)
	}
	for _, dir := range commandSearchPath {
		if p, err := realExecutable(filepath.Join(dir, name)); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("grant: program %q not found in %s", name, strings.Join(commandSearchPath, string(os.PathListSeparator)))
}

func realExecutable(path string) (string, error) {
	real, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("grant: program %q: %w", path, err)
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", fmt.Errorf("grant: program %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0) {
		return "", fmt.Errorf("grant: program %q is not an executable file", path)
	}
	return real, nil
}

// commandPattern returns the grant's argument pattern. Grants written before
// arguments were stored keep only the command string; it is parsed the same
// way, and a grant whose program no longer resolves matches nothing.
func (g *Grant) commandPattern() []string {
	if len(g.CommandArgv) > 0 {
		return g.CommandArgv
	}
	argv, err := parseCommandPattern(g.Command)
	if err != nil {
		return nil
	}
	return argv
}

// commandMatches compares argv with pattern argument by argument. The
// programs must resolve to the same file; a trailing "*" accepts any further
// arguments, including none.
func commandMatches(pattern, argv []string) bool {
	if len(pattern) == 0 || len(argv) == 0 {
		return false
	}
	prog, err := resolveProgram(argv[0])
	if err != nil || prog != pattern[0] {
		return false
	}
	rest, args := pattern[1:], argv[1:]
	if n := len(rest); n > 0 && rest[n-1] == "*" {
		rest = rest[:n-1]
		if len(args) < len(rest) {
			return false
		}
		args = args[:len(rest)]
	}
	if len(args) != len(rest) {
		return false
	}
	for i := range rest {
		if args[i] != rest[i] {
			return false
		}
	}
	return true
}

func validateCWDPattern(pattern string) error {
	if pattern == "*" {
		return nil
	}
	dir, _ := cwdPatternDir(pattern)
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("grant: --cwd %q must be an absolute directory", pattern)
	}
	return nil
}

// cwdPatternDir splits "<dir>/*" into dir and true, and returns any other
// pattern unchanged with false.
func cwdPatternDir(pattern string) (string, bool) {
	if dir, ok := strings.CutSuffix(pattern, "/*"); ok {
		return dir, true
	}
	if dir, ok := strings.CutSuffix(pattern, string(filepath.Separator)+"*"); ok {
		return dir, true
	}
	return pattern, false
}

// cwdMatches matches a working directory against pattern: "*" matches any
// directory, "<dir>/*" matches dir and everything below it, anything else
// only dir itself. Both sides are compared after resolving symlinks, so a
// link inside the granted tree cannot point the grant somewhere else, and
// case-insensitively where the file system usually is.
func cwdMatches(pattern, cwd string) bool {
	if cwd == "" || !filepath.IsAbs(cwd) {
		return false
	}
	if pattern == "*" {
		return true
	}
	dir, subtree := cwdPatternDir(pattern)
	realDir, err := filepath.EvalSymlinks(filepath.Clean(dir))
	if err != nil {
		return false
	}
	realCWD, err := filepath.EvalSymlinks(filepath.Clean(cwd))
	if err != nil {
		return false
	}
	if caseInsensitivePaths() {
		realDir, realCWD = strings.ToLower(realDir), strings.ToLower(realCWD)
	}
	if realCWD == realDir {
		return true
	}
	if !subtree {
		return false
	}
	rel, err := filepath.Rel(realDir, realCWD)
	return err == nil && filepath.IsLocal(rel)
}

func caseInsensitivePaths() bool {
	return runtime.GOOS == "darwin" || runtime.GOOS == "windows"
}
