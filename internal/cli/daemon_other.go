//go:build !darwin

package cli

// desktopAppRunning reports whether the desktop app manages keylatchd.
// Only meaningful on macOS; other platforms always return false.
func desktopAppRunning() bool { return false }
