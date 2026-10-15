//go:build linux

package control

import (
	"net"
	"syscall"
)

// Peer is the kernel-attested identity of the process on the other end of a
// Unix socket.
type Peer struct {
	UID uint32
	// PID is 0 when the peer lives in a PID namespace the daemon cannot see.
	PID int
}

func peerOf(c *net.UnixConn) (Peer, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var cred *syscall.Ucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		cred, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return Peer{}, err
	}
	if sockErr != nil {
		return Peer{}, sockErr
	}
	return Peer{UID: cred.Uid, PID: int(cred.Pid)}, nil
}
