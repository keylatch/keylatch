package brokerd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/brokerd/keys"
	"github.com/keylatch/keylatch/internal/control"
)

type fakeWinHost struct {
	elevated bool
	missing  map[string]bool
	dirs     map[string]string
	exists   bool
	created  []ServiceSpec
	started  int
	store    *fakeStore
	sids     map[string]string
	failDir  error
	failSvc  error
	failRun  error
}

func (h *fakeWinHost) Elevated() bool { return h.elevated }
func (h *fakeWinHost) Binary(name string) (string, error) {
	if h.missing[name] {
		return "", errScript
	}
	return `C:\Program Files\Keylatch\` + name, nil
}

func (h *fakeWinHost) SecureDir(path, sddl string) error {
	if h.failDir != nil {
		return h.failDir
	}
	if h.dirs == nil {
		h.dirs = map[string]string{}
	}
	h.dirs[path] = sddl
	return nil
}
func (h *fakeWinHost) ServiceExists(string) (bool, error) { return h.exists, nil }
func (h *fakeWinHost) CreateService(s ServiceSpec) error {
	h.created = append(h.created, s)
	return h.failSvc
}
func (h *fakeWinHost) StartService(string) error       { h.started++; return nil }
func (h *fakeWinHost) RootStore(string) keys.RootStore { return h.store }
func (h *fakeWinHost) ResolveSID(a string) (string, error) {
	if sid, ok := h.sids[a]; ok {
		return sid, nil
	}
	return "", errScript
}

func TestWindowsInstallFreshHost(t *testing.T) {
	host := &fakeWinHost{elevated: true, store: &fakeStore{}}
	run := &scriptRunner{}
	in := &WindowsInstaller{Host: host, Run: run, StateRoot: `C:\ProgramData\keylatch`}
	res, err := in.Install(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	svcSID := ServiceSID("keylatch")
	if got := host.dirs[`C:\ProgramData\keylatch`]; got != DirSDDL(svcSID) {
		t.Fatalf("state descriptor = %q", got)
	}
	var presence string
	for dir, sddl := range host.dirs {
		if sddl == AdminDirSDDL(svcSID) {
			presence = dir
		}
	}
	if presence == "" || !strings.HasSuffix(presence, WindowsAdminDirName) {
		t.Fatalf("presence directory = %q in %v", presence, host.dirs)
	}
	if len(host.created) != 1 || host.created[0].Account != `NT SERVICE\keylatch` || host.created[0].Exe != `C:\Program Files\Keylatch\keylatchd.exe` {
		t.Fatalf("service = %+v", host.created)
	}
	if got := strings.Join(host.created[0].Args, " "); !strings.Contains(got, "broker --service --state") {
		t.Fatalf("service arguments = %s", got)
	}
	if host.started != 1 || !res.RootCreated {
		t.Fatalf("started %d, result %+v", host.started, res)
	}
	if !run.called(`reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v KeylatchPresence /t REG_SZ /d "C:\Program Files\Keylatch\keylatch-presence.exe" serve /f`) {
		t.Fatalf("calls = %v", run.calls)
	}
}

func TestWindowsInstallRepeatsAndRefuses(t *testing.T) {
	host := &fakeWinHost{elevated: true, exists: true, store: &fakeStore{exists: true}, missing: map[string]bool{"keylatch-presence.exe": true}}
	run := &scriptRunner{}
	res, err := (&WindowsInstaller{Host: host, Run: run}).Install(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(host.created) != 0 || res.RootCreated || run.called("reg") {
		t.Fatalf("a repeat run changed the machine: %+v %v", res, run.calls)
	}
	if host.started != 1 {
		t.Fatal("the service was not started")
	}

	host = &fakeWinHost{elevated: false, store: &fakeStore{}}
	if _, err := (&WindowsInstaller{Host: host, Run: run}).Install(context.Background()); !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("not elevated = %v", err)
	}
	host = &fakeWinHost{elevated: true, store: &fakeStore{}, missing: map[string]bool{"keylatchd.exe": true}}
	if _, err := (&WindowsInstaller{Host: host, Run: run}).Install(context.Background()); err == nil {
		t.Fatal("a missing daemon binary was accepted")
	}
	host = &fakeWinHost{elevated: true, store: &fakeStore{}, failDir: errScript}
	if _, err := (&WindowsInstaller{Host: host, Run: run}).Install(context.Background()); !errors.Is(err, errScript) {
		t.Fatalf("a directory failure = %v", err)
	}
	host = &fakeWinHost{elevated: true, store: &fakeStore{err: errScript}}
	if _, err := (&WindowsInstaller{Host: host, Run: run}).Install(context.Background()); !errors.Is(err, errScript) {
		t.Fatalf("a root store failure = %v", err)
	}
	host = &fakeWinHost{elevated: true, store: &fakeStore{}, failSvc: errScript}
	if _, err := (&WindowsInstaller{Host: host, Run: run}).Install(context.Background()); !errors.Is(err, errScript) {
		t.Fatalf("a service failure = %v", err)
	}
	host = &fakeWinHost{elevated: true, store: &fakeStore{}}
	if _, err := (&WindowsInstaller{Host: host, Run: &scriptRunner{fail: map[string]error{"reg": errScript}}}).Install(context.Background()); !errors.Is(err, errScript) {
		t.Fatalf("a registry failure = %v", err)
	}
}

func TestEnrollWindows(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pem := pemOf(t, &k.PublicKey)
	dir := t.TempDir()
	host := &fakeWinHost{elevated: true, sids: map[string]string{`PC\alice`: sidAlice, `NT AUTHORITY\SYSTEM`: sidSystem}}
	path, err := EnrollWindows(host, dir, `PC\alice`, pem)
	if err != nil || path != filepath.Join(dir, "presence", sidAlice+".pem") {
		t.Fatalf("enroll = %q, %v", path, err)
	}
	// The service finds the key through the account map.
	m, _ := OpenAccounts(filepath.Join(t.TempDir(), "a.json"))
	uid, _ := m.UID(sidAlice)
	keyDir := filepath.Join(dir, "presence")
	if _, err := (DirKeys{Dir: keyDir, NameOf: m.SID}).PresenceKey(uid); err != nil {
		t.Fatalf("the service cannot load the enrolled key: %v", err)
	}
	if _, err := (DirKeys{Dir: keyDir, NameOf: m.SID}).PresenceKey(uid + 1); !errors.Is(err, ErrNoPresenceKey) {
		t.Fatalf("an unmapped user = %v", err)
	}
	if _, err := EnrollWindows(host, dir, `NT AUTHORITY\SYSTEM`, pem); !errors.Is(err, ErrNotUser) {
		t.Fatalf("SYSTEM = %v", err)
	}
	if _, err := EnrollWindows(host, dir, `PC\nobody`, pem); err == nil {
		t.Fatal("an unknown account enrolled")
	}
	if _, err := EnrollWindows(host, dir, `PC\alice`, []byte("junk")); err == nil {
		t.Fatal("junk enrolled")
	}
	host.elevated = false
	if _, err := EnrollWindows(host, dir, `PC\alice`, pem); !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("not elevated = %v", err)
	}
	if err := (DirKeys{Dir: dir}).EnrollNamed(`..\evil`, pem); err == nil {
		t.Fatal("a key name escaped the directory")
	}
}

func TestWinHelperAdmit(t *testing.T) {
	admit := winHelperAdmit(`C:\Program Files\Keylatch`)
	ctx := context.Background()
	if err := admit(ctx, control.Peer{Exe: `c:\program files\keylatch\Keylatch-Presence.exe`}); err != nil {
		t.Fatalf("the installed helper = %v", err)
	}
	for _, exe := range []string{`C:\Users\alice\keylatch-presence.exe`, `C:\Program Files\Keylatch\keylatch.exe`, `C:\Program Files\Keylatch\..\Evil\keylatch-presence.exe`, ""} {
		if admit(ctx, control.Peer{Exe: exe}) == nil {
			t.Errorf("%q was admitted", exe)
		}
	}
}

func TestApplyWindowsFillsInWhatIsUnset(t *testing.T) {
	o := Options{StateRoot: filepath.Join(t.TempDir(), "keylatch")}
	called := false
	err := o.applyWindows(&fakeStore{}, `C:\Program Files\Keylatch`, func(a *AccountMap) func(control.Conn) (*Identity, error) {
		called = a != nil
		return func(control.Conn) (*Identity, error) { return nil, ErrUnsupported }
	})
	if err != nil || !called {
		t.Fatalf("apply = %v (identify built: %v)", err, called)
	}
	sp, ok := o.Presence.(*SignedPresence)
	if o.Root == nil || o.Identify == nil || o.Helpers == nil || o.HelperAdmit == nil || !ok || sp.Name() != "windows-hello" {
		t.Fatalf("options = %+v", o)
	}
	if dk := sp.Keys.(DirKeys); !strings.HasSuffix(filepath.ToSlash(dk.Dir), WindowsAdminDirName+"/presence") {
		t.Fatalf("presence keys in %s", dk.Dir)
	}
	corrupt := Options{StateRoot: t.TempDir()}
	if err := writeFileForTest(filepath.Join(corrupt.StateRoot, "accounts.json"), "{"); err != nil {
		t.Fatal(err)
	}
	if err := corrupt.applyWindows(&fakeStore{}, "", nil); err == nil {
		t.Fatal("a corrupt account map was accepted")
	}
}
