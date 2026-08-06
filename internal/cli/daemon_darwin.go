//go:build darwin

package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	launchdLabel     = "io.keylatch.keylatchd"
	launchdPlistName = launchdLabel + ".plist"
)

// desktopAppRunning returns true when Keylatch.app is the process managing
// keylatchd. In that case the launchd service must NOT be started — the app
// owns the daemon lifecycle and both would compete for port 7890.
func desktopAppRunning() bool {
	// pgrep for a keylatchd process whose executable path is inside Keylatch.app
	out, err := exec.Command("pgrep", "-fl", "keylatchd").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "Keylatch.app")
}

const launchdPlistContentTpl = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>io.keylatch.keylatchd</string>
    <key>ProgramArguments</key><array><string>%s</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>%s/Library/Logs/keylatchd.log</string>
    <key>StandardErrorPath</key><string>%s/Library/Logs/keylatchd.log</string>
</dict>
</plist>
`

// launchdPlistPath returns the canonical path for the keylatchd launchd plist.
func launchdPlistPath() string {
	return os.ExpandEnv("$HOME/Library/LaunchAgents/" + launchdPlistName)
}

// findKeylatchd locates the keylatchd binary. It first checks next to the
// running keylatch binary, then falls back to PATH.
func findKeylatchd() (string, error) {
	self, err := os.Executable()
	if err == nil {
		candidate := filepath.Join(filepath.Dir(self), "keylatchd")
		if _, statErr := os.Stat(candidate); statErr == nil {
			return candidate, nil
		}
	}
	path, err := exec.LookPath("keylatchd")
	if err == nil {
		return path, nil
	}
	return "", errors.New("keylatchd binary not found next to keylatch or in PATH")
}

// installLaunchdPlist writes the keylatchd launchd plist to plistPath.
// It locates the keylatchd binary, creates ~/Library/LaunchAgents/ if needed,
// and writes the plist file.
func installLaunchdPlist(plistPath string) error {
	keylatchdPath, err := findKeylatchd()
	if err != nil {
		return fmt.Errorf("install launchd plist: %w", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("install launchd plist: resolve home dir: %w", err)
	}

	launchAgentsDir := filepath.Dir(plistPath)
	if mkErr := os.MkdirAll(launchAgentsDir, 0o755); mkErr != nil {
		return fmt.Errorf("install launchd plist: mkdir %q: %w", launchAgentsDir, mkErr)
	}

	content := fmt.Sprintf(launchdPlistContentTpl, keylatchdPath, home, home)
	if writeErr := os.WriteFile(plistPath, []byte(content), 0o644); writeErr != nil {
		return fmt.Errorf("install launchd plist: write %q: %w", plistPath, writeErr)
	}

	return nil
}
