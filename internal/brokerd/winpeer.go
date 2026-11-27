package brokerd

import (
	"errors"
	"fmt"

	"github.com/keylatch/keylatch/internal/control"
)

// winProc is an open handle to a client process. Holding the handle keeps the
// process object alive, so its PID cannot be reused while the handle is open.
type winProc interface {
	// SID is the account SID of the process token.
	SID() (string, error)
	// Start is the process creation time.
	Start() (string, error)
	Exe() string
	ParentPID() int
	// Alive reports whether the process is still running.
	Alive() bool
	Close()
}

// winSystem is the set of Windows calls peer identification makes; tests
// replace it.
type winSystem interface {
	// Client returns the process id and logon session of the pipe client
	// (GetNamedPipeClientProcessId, GetNamedPipeClientSessionId).
	Client(control.Conn) (pid int, session uint32, err error)
	Open(pid int) (winProc, error)
}

// ErrNotInteractive means the client does not run in an interactive logon
// session.
var ErrNotInteractive = errors.New("brokerd: the peer is not in an interactive logon session")

// ErrNotUser means the peer's token belongs to an account that is not a user of
// the broker.
var ErrNotUser = errors.New("brokerd: the peer's account is not a user account")

// WindowsIdentifier identifies pipe clients by their process token.
type WindowsIdentifier struct {
	Sys      winSystem
	Accounts *AccountMap
}

// Identify implements the Config.Identify contract.
func (w WindowsIdentifier) Identify(c control.Conn) (*Identity, error) {
	pid, session, err := w.Sys.Client(c)
	if err != nil {
		return nil, err
	}
	if pid <= 0 {
		return nil, ErrNoPID
	}
	if session == 0 {
		return nil, ErrNotInteractive
	}
	proc, err := w.Sys.Open(pid)
	if err != nil {
		return nil, errors.Join(ErrPeerGone, err)
	}
	sid, err := proc.SID()
	if err != nil {
		proc.Close()
		return nil, fmt.Errorf("brokerd: read the peer's token: %w", err)
	}
	if !IsUserSID(sid) {
		proc.Close()
		return nil, fmt.Errorf("%w: %s", ErrNotUser, sid)
	}
	start, err := proc.Start()
	if err != nil {
		proc.Close()
		return nil, errors.Join(ErrPeerGone, err)
	}
	uid, err := w.Accounts.UID(sid)
	if err != nil {
		proc.Close()
		return nil, err
	}
	id := &Identity{UID: uid, PID: pid, Start: start, SID: sid, Session: session, Exe: proc.Exe(), ParentPID: proc.ParentPID(), pin: &winPin{proc: proc}}
	if err := id.Verify(); err != nil {
		id.Close()
		return nil, err
	}
	return id, nil
}

type winPin struct{ proc winProc }

func (p *winPin) verify(id *Identity) error {
	if !p.proc.Alive() {
		return ErrPeerGone
	}
	if start, err := p.proc.Start(); err != nil || start != id.Start {
		return ErrPeerGone
	}
	return nil
}

func (p *winPin) close() { p.proc.Close() }
