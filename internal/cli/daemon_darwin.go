//go:build darwin

package cli

import (
	"os/exec"
	"strings"
)

// desktopAppRunning returns true when Keylatch.app is the process managing
// keylatchd. In that case the launchd service must NOT be started — the app
// owns the daemon lifecycle and both would compete for port 7890.
func desktopAppRunning() bool {
	out, err := exec.Command("pgrep", "-fl", "keylatchd").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "Keylatch.app")
}
