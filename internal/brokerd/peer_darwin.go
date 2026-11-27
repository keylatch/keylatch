package brokerd

import (
	"fmt"
	"net"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/keylatch/keylatch/internal/control"
)

// Identify reads the kernel-attested identity of the process on the other end
// of conn: LOCAL_PEERCRED, LOCAL_PEERPID and the LOCAL_PEERTOKEN audit token,
// which must agree, then the start time, parent and executable of the process.
// The executable's code signature is read once per binary and cached.
func Identify(conn control.Conn) (*Identity, error) {
	return MacIdentifier{Sys: darwinSystem{}, Code: &Codesign{Run: ExecRunner{}, Stat: statFile}}.Identify(conn)
}

func statFile(path string) (int64, time.Time, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, time.Time{}, err
	}
	return info.Size(), info.ModTime(), nil
}

type darwinSystem struct{}

func rawSocket(c control.Conn, f func(fd int) error) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return ErrUnsupported
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var inner error
	if err := raw.Control(func(fd uintptr) { inner = f(int(fd)) }); err != nil {
		return err
	}
	return inner
}

func (darwinSystem) PeerUID(c control.Conn) (uint32, error) {
	var uid uint32
	err := rawSocket(c, func(fd int) error {
		cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			return err
		}
		uid = cred.Uid
		return nil
	})
	return uid, err
}

func (darwinSystem) PeerPID(c control.Conn) (int, error) {
	var pid int
	err := rawSocket(c, func(fd int) (err error) {
		pid, err = unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		return err
	})
	return pid, err
}

func (darwinSystem) PeerToken(c control.Conn) (auditToken, error) {
	var tok auditToken
	err := rawSocket(c, func(fd int) error {
		n := uint32(unsafe.Sizeof(tok))
		// x/sys has no binary getsockopt wrapper: GetsockoptString stops at the
		// first NUL, which an audit token is full of.
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_LOCAL, unix.LOCAL_PEERTOKEN, //nolint:staticcheck // SA1019: no wrapper exists
			uintptr(unsafe.Pointer(&tok)), uintptr(unsafe.Pointer(&n)), 0) //nolint:gosec // G103: the kernel fills tok
		if errno != 0 {
			return errno
		}
		return nil
	})
	return tok, err
}

func (darwinSystem) Process(pid int) (macProc, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return macProc{}, err
	}
	if int(kp.Proc.P_pid) != pid {
		return macProc{}, fmt.Errorf("process %d is gone", pid)
	}
	p := macProc{
		Start: fmt.Sprintf("%d.%06d", kp.Proc.P_starttime.Sec, kp.Proc.P_starttime.Usec),
		PPID:  int(kp.Eproc.Ppid),
	}
	if raw, err := unix.SysctlRaw("kern.procargs2", pid); err == nil {
		p.Exe, _ = execPathOfProcArgs(raw)
	}
	return p, nil
}
