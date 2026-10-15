//go:build darwin

package control

import (
	"net"

	"golang.org/x/sys/unix"
)

// Peer is the kernel-attested identity of the process on the other end of a
// Unix socket.
type Peer struct {
	UID uint32
	PID int
}

func peerOf(c *net.UnixConn) (Peer, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var peer Peer
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			sockErr = err
			return
		}
		peer.UID = cred.Uid
		peer.PID, _ = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); err != nil {
		return Peer{}, err
	}
	return peer, sockErr
}
