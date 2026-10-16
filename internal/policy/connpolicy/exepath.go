package connpolicy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// isAbsPattern reports whether p is an absolute path on any platform: a policy
// document is shared between hosts, so a rule written with a Unix path or a
// drive path must read the same wherever the document is loaded.
func isAbsPattern(p string) bool {
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\\`) {
		return true
	}
	return len(p) >= 3 && p[1] == ':' && (p[2] == '/' || p[2] == '\\') &&
		(p[0] >= 'a' && p[0] <= 'z' || p[0] >= 'A' && p[0] <= 'Z')
}

// comparablePath puts a path in the form pattern matching compares: slash
// separators everywhere, and no case distinctions where the file system has
// none.
func comparablePath(p string) string {
	if runtime.GOOS != "windows" {
		return p
	}
	return strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
}

// hasPathSeparator reports whether a command word names a location rather than
// a program to look up.
func hasPathSeparator(argv0 string) bool {
	if runtime.GOOS == "windows" {
		return strings.ContainsAny(argv0, `/\`)
	}
	return strings.Contains(argv0, "/")
}

// executableNames lists the file names a command word can stand for. Windows
// runs a program by its extension, so a bare word also tries each PATHEXT one.
func executableNames(word string) []string {
	if runtime.GOOS != "windows" {
		return []string{word}
	}
	names := []string{word}
	if isExecutableName(word) {
		return names
	}
	for _, ext := range pathExtensions() {
		names = append(names, word+ext)
	}
	return names
}

func pathExtensions() []string {
	raw := os.Getenv("PATHEXT")
	if raw == "" {
		raw = ".COM;.EXE;.BAT;.CMD"
	}
	var exts []string
	for _, e := range filepath.SplitList(strings.ToLower(raw)) {
		if e != "" {
			exts = append(exts, e)
		}
	}
	return exts
}

// runnable reports whether a regular file can be started: it carries an
// execute bit, or on Windows a runnable extension.
func runnable(path string, info os.FileInfo) bool {
	if runtime.GOOS == "windows" {
		return isExecutableName(path)
	}
	return info.Mode()&0o111 != 0
}

// isExecutableName reports whether a Windows file name ends in an extension
// the system runs.
func isExecutableName(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	if ext == "" {
		return false
	}
	for _, e := range pathExtensions() {
		if e == ext {
			return true
		}
	}
	return false
}
