//go:build !windows

package llmcontext

import "syscall"

// setSocketUmask sets the process umask to 0o177 (allow only owner read/write)
// and returns the old umask so the caller can restore it after net.Listen.
// This prevents the socket from being world-accessible during the window
// between Listen and Chmod (TOCTOU fix).
func setSocketUmask() (old int) {
	return syscall.Umask(0o177)
}

// restoreUmask restores a previously saved umask value.
func restoreUmask(old int) {
	syscall.Umask(old)
}
