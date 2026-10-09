//go:build linux

package control

import (
	"fmt"
	"net"
	"os"
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

// sharesNamespaces reports whether pid is in the same PID, mount, user and
// network namespaces as this process. A process that cannot be inspected is
// treated as outside them.
func (p Peer) sharesNamespaces() bool {
	if p.PID <= 0 {
		return false
	}
	for _, ns := range []string{"pid", "mnt", "user", "net"} {
		if !sameNamespace(ns, p.PID) {
			return false
		}
	}
	return true
}

func sameNamespace(ns string, pid int) bool {
	mine, err := os.Stat("/proc/self/ns/" + ns)
	if err != nil {
		return false
	}
	theirs, err := os.Stat(fmt.Sprintf("/proc/%d/ns/%s", pid, ns))
	if err != nil {
		return false
	}
	return os.SameFile(mine, theirs)
}
