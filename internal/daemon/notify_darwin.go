//go:build darwin

package daemon

import (
	"os/exec"
	"strings"
)

// firstLaunchNotificationBody is the notification body shown on first daemon start.
// §2.6: exact text from spec.
const firstLaunchNotificationBody = "Keylatch is running. Open the app to connect your first provider, or run `keylatch connect openai` in your terminal."

// SendFirstLaunchNotification sends a macOS user notification via osascript
// (or terminal-notifier if it is available). It is a best-effort call:
// notification delivery failures are silently ignored to avoid breaking the
// daemon startup path.
//
// §2.6: uses osascript or terminal-notifier with a runtime check.
// Build tag ensures this file is only compiled on darwin.
func SendFirstLaunchNotification() {
	// Try terminal-notifier first — it supports actions and is preferred.
	if path, err := exec.LookPath("terminal-notifier"); err == nil {
		cmd := exec.Command(path,
			"-title", "Keylatch",
			"-message", firstLaunchNotificationBody,
			"-sound", "default",
		)
		_ = cmd.Run() // best-effort: ignore errors
		return
	}

	// Fall back to osascript (available on all macOS systems).
	// Escape single quotes in the notification body to avoid shell injection.
	body := strings.ReplaceAll(firstLaunchNotificationBody, `"`, `\"`)
	script := `display notification "` + body + `" with title "Keylatch"`
	cmd := exec.Command("osascript", "-e", script)
	_ = cmd.Run() // best-effort: ignore errors
}
