//go:build windows

package llmcontext

// setSocketUmask is a no-op on Windows. Windows does not support Unix-style
// umask; socket permissions are controlled via ACLs instead.
func setSocketUmask() (old int) { return 0 }

// restoreUmask is a no-op on Windows.
func restoreUmask(_ int) {}
