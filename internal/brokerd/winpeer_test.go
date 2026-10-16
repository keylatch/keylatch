package brokerd

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/control"
)

func TestServiceSIDMatchesWindows(t *testing.T) {
	// The SID Windows documents for the TrustedInstaller service.
	if got, want := ServiceSID("TrustedInstaller"), "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"; got != want {
		t.Fatalf("ServiceSID = %s, want %s", got, want)
	}
	if ServiceSID("keylatch") != ServiceSID("KEYLATCH") {
		t.Fatal("service names are case-insensitive")
	}
	if ServiceSID("keylatch") == ServiceSID("keylatch2") {
		t.Fatal("different services share a SID")
	}
}

func TestSecurityDescriptors(t *testing.T) {
	svc := ServiceSID("keylatch")
	pipe := PipeSDDL(svc)
	for _, want := range []string{"(D;;GA;;;NU)", "(A;;GA;;;SY)", "(A;;GA;;;" + svc + ")", "(A;;0x120183;;;IU)", "D:P"} {
		if !strings.Contains(pipe, want) {
			t.Errorf("pipe descriptor %q lacks %s", pipe, want)
		}
	}
	// Generic write would include FILE_CREATE_PIPE_INSTANCE.
	if strings.Contains(pipe, "GW") || strings.Contains(pipe, ";GRGW;") {
		t.Errorf("clients may create pipe instances: %s", pipe)
	}
	if mask := uint32(0x120183); mask&0x4 != 0 {
		t.Fatal("the client mask includes FILE_CREATE_PIPE_INSTANCE")
	}
	dir := DirSDDL(svc)
	if dir != "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;"+svc+")" || strings.Count(dir, "(A;") != 2 {
		t.Fatalf("directory descriptor = %s", dir)
	}
}

func TestIsUserSID(t *testing.T) {
	for sid, want := range map[string]bool{
		"S-1-5-21-1-2-3-1001": true,
		"S-1-12-1-1-2-3-4":    true,
		"S-1-5-18":            false,
		"S-1-5-19":            false,
		"S-1-5-32-544":        false,
		"S-1-5-80-1-2-3-4-5":  false,
		"":                    false,
	} {
		if IsUserSID(sid) != want {
			t.Errorf("IsUserSID(%q) != %v", sid, want)
		}
	}
}

func TestAccountMap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "accounts.json")
	m, err := OpenAccounts(path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := m.UID("S-1-5-21-1-2-3-1001")
	if err != nil || a != firstAccountID {
		t.Fatalf("first = %d, %v", a, err)
	}
	b, _ := m.UID("S-1-5-21-1-2-3-1002")
	if b != a+1 {
		t.Fatalf("second = %d", b)
	}
	if again, _ := m.UID("S-1-5-21-1-2-3-1001"); again != a {
		t.Fatalf("a known SID moved to %d", again)
	}
	if _, ok := m.Find("S-1-5-21-9"); ok {
		t.Fatal("an unknown SID was found")
	}
	if sid, ok := m.SID(b); !ok || sid != "S-1-5-21-1-2-3-1002" {
		t.Fatalf("SID(%d) = %q", b, sid)
	}
	if _, ok := m.SID(7); ok {
		t.Fatal("an unassigned id resolved")
	}

	// A restart keeps the numbering.
	re, err := OpenAccounts(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := re.Find("S-1-5-21-1-2-3-1002"); !ok || got != b {
		t.Fatalf("after restart = %d, %v", got, ok)
	}
	if c, _ := re.UID("S-1-5-21-1-2-3-1003"); c != b+1 {
		t.Fatalf("numbering continued at %d", c)
	}

	if _, err := OpenAccounts(t.TempDir()); err == nil {
		t.Fatal("a directory opened as the accounts file")
	}
}

func TestAccountMapBounds(t *testing.T) {
	dir := t.TempDir()
	m, _ := OpenAccounts(filepath.Join(dir, "a.json"))
	m.next = DefaultMaxUID + 1
	if _, err := m.UID("S-1-5-21-5"); !errors.Is(err, ErrAccountsFull) {
		t.Fatalf("full = %v", err)
	}
	// A save failure leaves no half-assigned account behind.
	bad, _ := OpenAccounts(filepath.Join(dir, "file", "a.json"))
	if err := writeFileForTest(filepath.Join(dir, "file"), "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := bad.UID("S-1-5-21-6"); err == nil {
		t.Fatal("a failed save was ignored")
	}
	if _, ok := bad.Find("S-1-5-21-6"); ok {
		t.Fatal("a failed save kept the account")
	}
	corrupt := filepath.Join(dir, "c.json")
	if err := writeFileForTest(corrupt, "{"); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAccounts(corrupt); err == nil {
		t.Fatal("a corrupt accounts file opened")
	}
}

type fakeWinProc struct {
	sid, start, exe string
	ppid            int
	dead            bool
	sidErr          error
	startErr        error
	closed          bool
}

func (p *fakeWinProc) SID() (string, error)   { return p.sid, p.sidErr }
func (p *fakeWinProc) Start() (string, error) { return p.start, p.startErr }
func (p *fakeWinProc) Exe() string            { return p.exe }
func (p *fakeWinProc) ParentPID() int         { return p.ppid }
func (p *fakeWinProc) Alive() bool            { return !p.dead }
func (p *fakeWinProc) Close()                 { p.closed = true }

type fakeWinSys struct {
	pid     int
	session uint32
	cliErr  error
	proc    *fakeWinProc
	openErr error
}

func (f *fakeWinSys) Client(control.Conn) (int, uint32, error) { return f.pid, f.session, f.cliErr }
func (f *fakeWinSys) Open(int) (winProc, error) {
	if f.openErr != nil {
		return nil, f.openErr
	}
	return f.proc, nil
}

func winIdentifier(t *testing.T, sys *fakeWinSys) WindowsIdentifier {
	t.Helper()
	m, err := OpenAccounts(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	return WindowsIdentifier{Sys: sys, Accounts: m}
}

func goodWin() *fakeWinSys {
	return &fakeWinSys{pid: 4242, session: 2, proc: &fakeWinProc{sid: "S-1-5-21-1-2-3-1001", start: "133700000000000000", exe: `C:\Program Files\Keylatch\keylatch.exe`, ppid: 100}}
}

func TestWindowsIdentifierBuildsAnIdentity(t *testing.T) {
	sys := goodWin()
	w := winIdentifier(t, sys)
	id, err := w.Identify(nil)
	if err != nil {
		t.Fatal(err)
	}
	if id.UID != firstAccountID || id.PID != 4242 || id.SID != "S-1-5-21-1-2-3-1001" || id.Session != 2 || id.ParentPID != 100 || id.Exe == "" || id.Start == "" {
		t.Fatalf("identity = %+v", id)
	}
	if p := id.Peer(); p.SID != id.SID || p.Exe != id.Exe {
		t.Fatalf("peer = %+v", p)
	}
	// The same person gets the same partition on the next connection.
	again, err := w.Identify(nil)
	if err != nil || again.UID != id.UID {
		t.Fatalf("second connection = %+v, %v", again, err)
	}
	again.Close()
	if err := id.Verify(); err != nil {
		t.Fatalf("verify = %v", err)
	}
	sys.proc.start = "other"
	if err := id.Verify(); !errors.Is(err, ErrPeerGone) {
		t.Fatalf("a changed creation time = %v", err)
	}
	sys.proc.start = "133700000000000000"
	sys.proc.dead = true
	if err := id.Verify(); !errors.Is(err, ErrPeerGone) {
		t.Fatalf("an exited peer = %v", err)
	}
	id.Close()
	if !sys.proc.closed {
		t.Fatal("the process handle stayed open")
	}
}

func TestWindowsIdentifierRefusals(t *testing.T) {
	try := func(mutate func(*fakeWinSys)) (*fakeWinSys, error) {
		sys := goodWin()
		mutate(sys)
		id, err := winIdentifier(t, sys).Identify(nil)
		if err == nil {
			id.Close()
		}
		return sys, err
	}
	if _, err := try(func(s *fakeWinSys) { s.cliErr = errScript }); !errors.Is(err, errScript) {
		t.Fatalf("no client = %v", err)
	}
	if _, err := try(func(s *fakeWinSys) { s.pid = 0 }); !errors.Is(err, ErrNoPID) {
		t.Fatalf("pid 0 = %v", err)
	}
	if _, err := try(func(s *fakeWinSys) { s.session = 0 }); !errors.Is(err, ErrNotInteractive) {
		t.Fatalf("session 0 = %v", err)
	}
	if _, err := try(func(s *fakeWinSys) { s.openErr = errScript }); !errors.Is(err, ErrPeerGone) {
		t.Fatalf("a process that cannot be opened = %v", err)
	}
	if sys, err := try(func(s *fakeWinSys) { s.proc.sid = "S-1-5-18" }); !errors.Is(err, ErrNotUser) || !sys.proc.closed {
		t.Fatalf("SYSTEM = %v (closed %v)", err, sys.proc.closed)
	}
	if sys, err := try(func(s *fakeWinSys) { s.proc.sidErr = errScript }); !errors.Is(err, errScript) || !sys.proc.closed {
		t.Fatalf("an unreadable token = %v", err)
	}
	if sys, err := try(func(s *fakeWinSys) { s.proc.startErr = errScript }); !errors.Is(err, ErrPeerGone) || !sys.proc.closed {
		t.Fatalf("no creation time = %v", err)
	}
	sys := goodWin()
	w := winIdentifier(t, sys)
	w.Accounts.next = DefaultMaxUID + 1
	if _, err := w.Identify(nil); !errors.Is(err, ErrAccountsFull) || !sys.proc.closed {
		t.Fatalf("no partition ids = %v", err)
	}
}
