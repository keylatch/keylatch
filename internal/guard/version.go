package guard

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

const versionMarker = "keylatch-hook-version:"

// ScriptVersion returns the version stamped in a guard script's header
// ("# keylatch-hook-version: N"), or 0 when the script carries none.
func ScriptVersion(script []byte) int {
	sc := bufio.NewScanner(bytes.NewReader(script))
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(sc.Text()), "#"))
		if rest, ok := strings.CutPrefix(line, versionMarker); ok {
			n, err := strconv.Atoi(strings.TrimSpace(rest))
			if err != nil {
				return 0
			}
			return n
		}
	}
	return 0
}

// ClaudeCodeVersion is the version of the Claude Code guard script this build
// installs.
func ClaudeCodeVersion() int { return ScriptVersion(ClaudeCodeScript) }
