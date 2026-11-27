//go:build darwin

package keychain_test

import (
	"regexp"
	"strings"

	kexec "github.com/keylatch/keylatch/internal/exec"
)

// securityLine is the command line a security call ran: its arguments, or for
// an interactive `-i` call the script it read from stdin.
func securityLine(c kexec.MockCall) string {
	if len(c.Args) == 1 && c.Args[0] == "-i" {
		return strings.TrimSpace(string(c.Stdin))
	}
	return strings.Join(c.Args, " ")
}

// scriptFlagValue returns the value after flag in a security command line,
// unquoted when it was written in double quotes.
func scriptFlagValue(line, flag string) (string, bool) {
	re := regexp.MustCompile(`(?:^|\s)` + regexp.QuoteMeta(flag) + `\s+(?:"((?:[^"\\]|\\.)*)"|(\S+))`)
	m := re.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	if m[2] != "" {
		return m[2], true
	}
	return strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(m[1]), true
}
