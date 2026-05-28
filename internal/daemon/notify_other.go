//go:build !darwin

package daemon

// SendFirstLaunchNotification is a no-op on non-macOS platforms.
// §2.6: build guard ensures this compiles and runs correctly on Linux/Windows.
func SendFirstLaunchNotification() {}
