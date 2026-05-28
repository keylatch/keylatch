//go:build darwin

package mcp

import "golang.org/x/sys/unix"

// getPeerUID returns the UID of the connecting peer using LOCAL_PEERCRED on macOS.
// Returns -1 on error so that the check fails safely.
func getPeerUID(fd int, _ int) int {
	ucred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return -1
	}
	return int(ucred.Uid)
}
