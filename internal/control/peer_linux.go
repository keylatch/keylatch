//go:build linux

package control

import (
	"net"
	"syscall"
)

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
