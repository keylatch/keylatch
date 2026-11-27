package brokerd

import (
	"fmt"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/winpipe"
)

// Identify is unavailable without an account map; the service installs a
// WindowsIdentifier through Options.
func Identify(control.Conn) (*Identity, error) { return nil, ErrUnsupported }

type winListener struct{ *winpipe.Listener }

func (l winListener) Accept() (control.Conn, error) { return l.Listener.Accept() }

// listenPipe opens the broker pipe with the service's security descriptor.
func listenPipe(name string) (Listener, error) {
	l, err := winpipe.Listen(name, PipeSDDL(ServiceSID(WindowsServiceName)))
	if err != nil {
		return nil, fmt.Errorf("brokerd: listen on %s: %w", name, err)
	}
	return winListener{l}, nil
}

type windowsSystem struct{}

func (windowsSystem) Client(c control.Conn) (int, uint32, error) {
	pc, ok := c.(*winpipe.Conn)
	if !ok {
		return 0, 0, ErrUnsupported
	}
	pid, session, err := pc.ClientProcess()
	return int(pid), session, err
}

func (windowsSystem) Open(pid int) (winProc, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid)) //nolint:gosec // G115: a PID is non-negative
	if err != nil {
		return nil, err
	}
	p := &realProc{h: h}
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	defer func() { _ = tok.Close() }()
	user, err := tok.GetTokenUser()
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	p.sid = user.User.Sid.String()
	var created, exited, kernel, usr windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &usr); err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	p.start = strconv.FormatUint(uint64(created.HighDateTime)<<32|uint64(created.LowDateTime), 10)
	p.exe = imagePath(h)
	p.ppid = parentOf(uint32(pid)) //nolint:gosec // G115: see above
	return p, nil
}

func imagePath(h windows.Handle) string {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

func parentOf(pid uint32) int {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer func() { _ = windows.CloseHandle(snap) }()
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err := windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if e.ProcessID == pid {
			return int(e.ParentProcessID)
		}
	}
	return 0
}

type realProc struct {
	h     windows.Handle
	sid   string
	start string
	exe   string
	ppid  int
}

func (p *realProc) SID() (string, error)   { return p.sid, nil }
func (p *realProc) Start() (string, error) { return p.start, nil }
func (p *realProc) Exe() string            { return p.exe }
func (p *realProc) ParentPID() int         { return p.ppid }
func (p *realProc) Close()                 { _ = windows.CloseHandle(p.h) }

// Alive reports whether the process has not exited. The open handle keeps its
// PID from being reused, so a live handle is the same process that connected.
func (p *realProc) Alive() bool {
	var code uint32
	if err := windows.GetExitCodeProcess(p.h, &code); err != nil {
		return false
	}
	return code == stillActive
}

const stillActive = 259
