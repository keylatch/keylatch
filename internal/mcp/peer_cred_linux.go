//go:build linux

package mcp

import "syscall"

// getPeerUID returns the UID of the connecting peer using SO_PEERCRED.
// Returns serverUID on error so that the check fails safely.
func getPeerUID(fd int, serverUID int) int {
	ucred, err := syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return -1
	}
	return int(ucred.Uid)
}
