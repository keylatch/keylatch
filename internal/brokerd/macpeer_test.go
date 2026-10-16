package brokerd

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/control"
)

type fakeMac struct {
	uid     uint32
	pid     int
	tok     auditToken
	procs   map[int]macProc
	credErr error
	pidErr  error
	tokErr  error
}

func (f *fakeMac) PeerUID(control.Conn) (uint32, error)       { return f.uid, f.credErr }
func (f *fakeMac) PeerPID(control.Conn) (int, error)          { return f.pid, f.pidErr }
func (f *fakeMac) PeerToken(control.Conn) (auditToken, error) { return f.tok, f.tokErr }
func (f *fakeMac) Process(pid int) (macProc, error) {
	p, ok := f.procs[pid]
	if !ok {
		return macProc{}, errors.New("no such process")
	}
	return p, nil
}

func goodMac() *fakeMac {
	return &fakeMac{
		uid: 501, pid: 777,
		tok:   auditToken{501, 501, 20, 501, 20, 777, 100005, 3},
		procs: map[int]macProc{777: {Start: "1790000000.000123", PPID: 1, Exe: "/Applications/Keylatch.app/Contents/MacOS/keylatch"}},
	}
}

type fixedCode string

func (f fixedCode) Identity(context.Context, int, string) (string, error) {
	if f == "" {
		return "", errors.New("unsigned")
	}
	return string(f), nil
}

func TestMacIdentifierBuildsAnIdentity(t *testing.T) {
	sys := goodMac()
	id, err := MacIdentifier{Sys: sys, Code: fixedCode("team=ABCDE12345;id=dev.keylatch.cli")}.Identify(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer id.Close()
	if id.UID != 501 || id.PID != 777 || id.Start != "1790000000.000123" || id.ParentPID != 1 || id.Code != "team=ABCDE12345;id=dev.keylatch.cli" || id.Exe == "" {
		t.Fatalf("identity = %+v", id)
	}
	if p := id.Peer(); p.Code != id.Code || p.ParentPID != 1 || p.Exe != id.Exe || p.Verify == nil {
		t.Fatalf("peer = %+v", p)
	}
	if err := id.Verify(); err != nil {
		t.Fatalf("verify = %v", err)
	}
	// The PID is reused by another process: start time differs.
	sys.procs[777] = macProc{Start: "1790000099.000001", PPID: 1}
	if err := id.Verify(); !errors.Is(err, ErrPeerGone) {
		t.Fatalf("a recycled pid = %v", err)
	}
	delete(sys.procs, 777)
	if err := id.Verify(); !errors.Is(err, ErrPeerGone) {
		t.Fatalf("an exited peer = %v", err)
	}
}

func TestMacIdentifierRefusals(t *testing.T) {
	id := func(mutate func(*fakeMac)) error {
		sys := goodMac()
		mutate(sys)
		got, err := MacIdentifier{Sys: sys}.Identify(nil)
		if err == nil {
			got.Close()
		}
		return err
	}
	if err := id(func(f *fakeMac) { f.credErr = errScript }); !errors.Is(err, errScript) {
		t.Fatalf("no credentials = %v", err)
	}
	if err := id(func(f *fakeMac) { f.pidErr = errScript }); !errors.Is(err, errScript) {
		t.Fatalf("no pid = %v", err)
	}
	if err := id(func(f *fakeMac) { f.pid = 0; f.tok[5] = 0 }); !errors.Is(err, ErrNoPID) {
		t.Fatalf("pid 0 = %v", err)
	}
	if err := id(func(f *fakeMac) { f.tokErr = errScript }); !errors.Is(err, errScript) {
		t.Fatalf("no token = %v", err)
	}
	if err := id(func(f *fakeMac) { f.tok[5] = 778 }); !errors.Is(err, ErrTokenMismatch) {
		t.Fatalf("token for another pid = %v", err)
	}
	if err := id(func(f *fakeMac) { f.tok[1] = 0 }); !errors.Is(err, ErrTokenMismatch) {
		t.Fatalf("token for another euid = %v", err)
	}
	if err := id(func(f *fakeMac) { delete(f.procs, 777) }); !errors.Is(err, ErrPeerGone) {
		t.Fatalf("a process that left = %v", err)
	}
}

func TestMacIdentifierUnsignedPeerHasNoCode(t *testing.T) {
	got, err := MacIdentifier{Sys: goodMac(), Code: fixedCode("")}.Identify(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	if got.Code != "" {
		t.Fatalf("an unsigned peer got a code identity: %q", got.Code)
	}
}

const signedDump = `Executable=/usr/local/libexec/keylatch/keylatchd
Identifier=dev.keylatch.broker
Format=Mach-O thin (arm64)
CodeDirectory v=20500 size=1234 flags=0x10000(runtime) hashes=30+7 location=embedded
CDHash=0123456789abcdef0123456789abcdef01234567
TeamIdentifier=ABCDE12345
`

func TestParseCodesign(t *testing.T) {
	ci, err := ParseCodesign(signedDump)
	if err != nil {
		t.Fatal(err)
	}
	if ci.Identifier != "dev.keylatch.broker" || ci.Team != "ABCDE12345" || !strings.HasPrefix(ci.CDHash, "0123") || ci.String() != "team=ABCDE12345;id=dev.keylatch.broker" {
		t.Fatalf("parsed = %+v", ci)
	}
	adhoc, err := ParseCodesign("Identifier=a.out\nTeamIdentifier=not set\n")
	if err != nil || adhoc.Team != "" {
		t.Fatalf("ad hoc = %+v, %v", adhoc, err)
	}
	if _, err := ParseCodesign("/bin/x: code object is not signed at all\n"); err == nil {
		t.Fatal("an unsigned binary parsed")
	}
}

func TestCodesignCachesByBinary(t *testing.T) {
	r := &scriptRunner{out: map[string]string{"/usr/bin/codesign -d --verbose=4": signedDump}, fail: map[string]error{"/usr/bin/codesign -d --verbose=4": errors.New("exit 1")}}
	mod := time.Unix(1790000000, 0)
	size := int64(100)
	c := &Codesign{Run: r, Stat: func(string) (int64, time.Time, error) { return size, mod, nil }}
	for range 3 {
		got, err := c.Identity(context.Background(), 1, "/bin/keylatch")
		if err != nil || got != "team=ABCDE12345;id=dev.keylatch.broker" {
			t.Fatalf("identity = %q, %v", got, err)
		}
	}
	if n := r.count("/usr/bin/codesign -d"); n != 1 {
		t.Fatalf("codesign ran %d times for one binary", n)
	}
	size = 200 // the binary was replaced
	if _, err := c.Identity(context.Background(), 1, "/bin/keylatch"); err != nil {
		t.Fatal(err)
	}
	if n := r.count("/usr/bin/codesign -d"); n != 2 {
		t.Fatalf("a changed binary must be read again; ran %d", n)
	}

	unsigned := &Codesign{Run: &scriptRunner{out: map[string]string{"/usr/bin/codesign": "x: code object is not signed at all\n"}}}
	if _, err := unsigned.Identity(context.Background(), 1, "/bin/x"); err == nil {
		t.Fatal("an unsigned binary has a code identity")
	}
}

func TestCodesignSatisfiesLiveProcess(t *testing.T) {
	r := &scriptRunner{}
	c := &Codesign{Run: r}
	if err := c.Satisfies(context.Background(), 42, "/bin/x", `identifier "dev.keylatch.cli"`); err != nil {
		t.Fatal(err)
	}
	if !r.called(`/usr/bin/codesign --verify --strict -R =identifier "dev.keylatch.cli" +42`) {
		t.Fatalf("calls = %v", r.calls)
	}
	if err := c.Satisfies(context.Background(), 0, "/bin/x", "anchor apple"); err != nil || !r.called(`/usr/bin/codesign --verify --strict -R =anchor apple /bin/x`) {
		t.Fatalf("path form: %v %v", err, r.calls)
	}
	bad := &Codesign{Run: &scriptRunner{fail: map[string]error{"/usr/bin/codesign": errScript}}}
	if err := bad.Satisfies(context.Background(), 42, "", "anchor apple"); err == nil {
		t.Fatal("a failed check passed")
	}
}

func TestDesignatedRequirement(t *testing.T) {
	r := &scriptRunner{out: map[string]string{"/usr/bin/codesign -d -r-": "Executable=/x\ndesignated => identifier \"dev.keylatch.broker\" and anchor apple generic\n"}}
	got, err := (&Codesign{Run: r}).DesignatedRequirement(context.Background(), "/x")
	if err != nil || got != `identifier "dev.keylatch.broker" and anchor apple generic` {
		t.Fatalf("requirement = %q, %v", got, err)
	}
	none := &Codesign{Run: &scriptRunner{out: map[string]string{"/usr/bin/codesign": "Executable=/x\n"}}}
	if _, err := none.DesignatedRequirement(context.Background(), "/x"); err == nil {
		t.Fatal("no requirement was reported as one")
	}
	if _, err := (&Codesign{Run: &scriptRunner{fail: map[string]error{"/usr/bin/codesign": errScript}}}).DesignatedRequirement(context.Background(), "/x"); err == nil {
		t.Fatal("a codesign failure passed")
	}
}

func TestExecPathOfProcArgs(t *testing.T) {
	raw := append([]byte{2, 0, 0, 0}, []byte("/usr/bin/true\x00/usr/bin/true\x00arg\x00")...)
	if got, err := execPathOfProcArgs(raw); err != nil || got != "/usr/bin/true" {
		t.Fatalf("path = %q, %v", got, err)
	}
	for _, bad := range [][]byte{nil, {1, 0, 0, 0}, {1, 0, 0, 0, 0, 'x'}} {
		if _, err := execPathOfProcArgs(bad); err == nil {
			t.Errorf("%v parsed", bad)
		}
	}
}
