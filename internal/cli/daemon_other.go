//go:build !darwin

package cli

import "errors"

var errNotSupported = errors.New("not supported on this platform")

// launchdPlistPath is a stub on non-Darwin platforms.
func launchdPlistPath() string {
	return ""
}

// findKeylatchd is a stub on non-Darwin platforms.
func findKeylatchd() (string, error) {
	return "", errNotSupported
}

// installLaunchdPlist is a stub on non-Darwin platforms.
func installLaunchdPlist(_ string) error {
	return errNotSupported
}

// desktopAppRunning is a stub on non-Darwin platforms — always false.
func desktopAppRunning() bool {
	return false
}
