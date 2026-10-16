//go:build linux

package brokerd

import (
	"errors"
	"net"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/keylatch/keylatch/internal/control"
)

// sys is the set of kernel calls peer identification makes; tests replace it.
var sys = system{
	readFile:    os.ReadFile,
	pidfdOpen:   func(pid int) (int, error) { return unix.PidfdOpen(pid, 0) },
	pidfdSignal: func(fd int) error { return unix.PidfdSendSignal(fd, 0, nil, 0) },
	closeFD:     func(fd int) { _ = unix.Close(fd) },
	peerCred:    peerCred,
	peerPidfd:   peerPidfd,
}

type system struct {
	readFile    func(string) ([]byte, error)
	pidfdOpen   func(pid int) (int, error)
	pidfdSignal func(fd int) error
	closeFD     func(fd int)
	peerCred    func(*net.UnixConn) (uid uint32, pid int, err error)
	peerPidfd   func(*net.UnixConn) (int, error)
}

// Identify reads the kernel-attested identity of the process on the other end
// of conn and pins it with a pidfd. SO_PEERPIDFD (Linux 6.5) hands over a pidfd
// for the exact process that connected; older kernels fall back to
// pidfd_open(pid), and the start time read afterwards catches a PID that was
// recycled in between.
func Identify(c control.Conn) (*Identity, error) {
	conn, ok := c.(*net.UnixConn)
	if !ok && c != nil {
		return nil, ErrUnsupported
	}
	uid, pid, err := sys.peerCred(conn)
	if err != nil {
		return nil, err
	}
	if pid <= 0 {
		return nil, ErrNoPID
	}
	fd, err := sys.peerPidfd(conn)
	if err != nil {
		if fd, err = sys.pidfdOpen(pid); err != nil {
			return nil, errors.Join(ErrPeerGone, err)
		}
	}
	id := &Identity{UID: uid, PID: pid, pin: &pidfdPin{fd: fd}}
	stat, err := sys.readFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		id.Close()
		return nil, errors.Join(ErrPeerGone, err)
	}
	if id.Start, err = ParseStartTime(string(stat)); err != nil {
		id.Close()
		return nil, err
	}
	if cg, err := sys.readFile("/proc/" + strconv.Itoa(pid) + "/cgroup"); err == nil {
		id.Cgroup = ParseCgroup(string(cg))
	}
	if err := id.Verify(); err != nil {
		id.Close()
		return nil, err
	}
	return id, nil
}

type pidfdPin struct{ fd int }

func (p *pidfdPin) verify(id *Identity) error {
	if err := sys.pidfdSignal(p.fd); err != nil {
		return errors.Join(ErrPeerGone, err)
	}
	stat, err := sys.readFile("/proc/" + strconv.Itoa(id.PID) + "/stat")
	if err != nil {
		return errors.Join(ErrPeerGone, err)
	}
	start, err := ParseStartTime(string(stat))
	if err != nil || start != id.Start {
		return ErrPeerGone
	}
	return nil
}

func (p *pidfdPin) close() { sys.closeFD(p.fd) }

func peerCred(c *net.UnixConn) (uint32, int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *syscall.Ucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		cred, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}
	if sockErr != nil {
		return 0, 0, sockErr
	}
	return cred.Uid, int(cred.Pid), nil
}

func peerPidfd(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	var fd int
	var sockErr error
	if err := raw.Control(func(s uintptr) {
		fd, sockErr = unix.GetsockoptInt(int(s), unix.SOL_SOCKET, unix.SO_PEERPIDFD)
	}); err != nil {
		return -1, err
	}
	return fd, sockErr
}
