package brokerd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/brokerd/keys"
	macospkg "github.com/keylatch/keylatch/packaging/macos"
)

type fakeStore struct {
	exists  bool
	created bool
	err     error
}

func (*fakeStore) Name() string          { return "fake keychain" }
func (*fakeStore) Load() ([]byte, error) { return nil, keys.ErrNoRoot }
func (f *fakeStore) Create(io.Reader) (bool, error) {
	f.created = !f.exists && f.err == nil
	return f.created, f.err
}

func macInstaller(t *testing.T, run Runner, store *fakeStore) *MacInstaller {
	t.Helper()
	root := t.TempDir()
	daemon := filepath.Join(root, macLibexec, "keylatchd")
	if err := os.MkdirAll(filepath.Dir(daemon), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(daemon, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &MacInstaller{
		Root: root, Files: macospkg.Files, Run: run, Euid: func() int { return 0 },
		RootStore: func(string, string, func(string) error) keys.RootStore { return store },
	}
}

func TestMacInstallFreshHost(t *testing.T) {
	run := &scriptRunner{
		fail: map[string]error{"dscl . -read /Users/_keylatch": errScript, "launchctl print": errScript},
		out: map[string]string{
			"dscl . -list /Users UniqueID":        "root 0\n_spotlight 89\n_svc300 300\n_svc301 301\nalice 501\n",
			"dscl . -list /Groups PrimaryGroupID": "wheel 0\n_grp302 302\n",
		},
	}
	store := &fakeStore{}
	in := macInstaller(t, run, store)
	var owned []string
	in.Own = func(p string) error { owned = append(owned, p); return nil }
	res, err := in.Install(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.RootCreated || !store.created {
		t.Fatalf("device root not created: %+v", res)
	}
	for _, want := range []string{
		"dscl . -create /Users/_keylatch UniqueID 303",
		"dscl . -create /Groups/_keylatch PrimaryGroupID 303",
		"dscl . -create /Users/_keylatch UserShell /usr/bin/false",
		"dscl . -create /Users/_keylatch IsHidden 1",
		"launchctl bootstrap system " + filepath.Join(in.Root, macDaemonPlist),
		"launchctl enable system/dev.keylatch.broker",
	} {
		if !run.called(want) {
			t.Errorf("missing command %q in %v", want, run.calls)
		}
	}
	if run.called("launchctl kickstart") {
		t.Error("a fresh install kicked a daemon that was not loaded")
	}
	for _, rel := range []string{macDaemonPlist, macPresencePlist} {
		if _, err := os.Stat(filepath.Join(in.Root, rel)); err != nil {
			t.Errorf("%s was not installed: %v", rel, err)
		}
	}
	info, err := os.Stat(filepath.Join(in.Root, macStateDir, "run"))
	if err != nil || !info.IsDir() {
		t.Fatalf("run dir: %v", err)
	}
	if len(owned) != 2 {
		t.Fatalf("directories handed to the service account: %v", owned)
	}
}

func TestMacInstallIsRepeatable(t *testing.T) {
	run := &scriptRunner{}
	store := &fakeStore{exists: true}
	in := macInstaller(t, run, store)
	if _, err := in.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	res, err := in.Install(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.RootCreated || len(res.Written) != 0 {
		t.Fatalf("a repeat run wrote: %+v", res)
	}
	if run.called("dscl . -create") {
		t.Fatal("an existing account was recreated")
	}
	if !run.called("launchctl kickstart -k system/dev.keylatch.broker") || run.called("launchctl bootstrap") {
		t.Fatalf("a loaded daemon must be restarted, not bootstrapped again: %v", run.calls)
	}
}

func TestMacInstallRefusals(t *testing.T) {
	in := macInstaller(t, &scriptRunner{}, &fakeStore{})
	in.Euid = func() int { return 501 }
	if _, err := in.Install(context.Background()); !errors.Is(err, ErrNotRoot) {
		t.Fatalf("non-root = %v", err)
	}

	in = macInstaller(t, &scriptRunner{}, &fakeStore{})
	_ = os.Remove(filepath.Join(in.Root, macLibexec, "keylatchd"))
	if _, err := in.Install(context.Background()); err == nil || !strings.Contains(err.Error(), "install the Keylatch package") {
		t.Fatalf("no daemon binary = %v", err)
	}

	in = macInstaller(t, &scriptRunner{}, &fakeStore{err: errScript})
	if _, err := in.Install(context.Background()); !errors.Is(err, errScript) {
		t.Fatalf("a root store failure = %v", err)
	}

	in = macInstaller(t, &scriptRunner{fail: map[string]error{"launchctl bootstrap": errScript, "launchctl print": errScript}}, &fakeStore{})
	if _, err := in.Install(context.Background()); !errors.Is(err, errScript) {
		t.Fatalf("a failed bootstrap = %v", err)
	}

	in = macInstaller(t, &scriptRunner{fail: map[string]error{"dscl . -create /Users/_keylatch UniqueID": errScript, "dscl . -read": errScript}}, &fakeStore{})
	if _, err := in.Install(context.Background()); !errors.Is(err, errScript) {
		t.Fatalf("a failed account creation = %v", err)
	}

	in = macInstaller(t, &scriptRunner{fail: map[string]error{"dscl . -list /Users": errScript, "dscl . -read": errScript}}, &fakeStore{})
	if _, err := in.Install(context.Background()); !errors.Is(err, errScript) {
		t.Fatalf("a failed account listing = %v", err)
	}

	in = macInstaller(t, &scriptRunner{}, &fakeStore{})
	in.Own = func(string) error { return errScript }
	if _, err := in.Install(context.Background()); !errors.Is(err, errScript) {
		t.Fatalf("a failed hand-over = %v", err)
	}

	in = macInstaller(t, &scriptRunner{fail: map[string]error{"launchctl enable": errScript}}, &fakeStore{})
	if _, err := in.Install(context.Background()); !errors.Is(err, errScript) {
		t.Fatalf("a failed enable = %v", err)
	}

	in = macInstaller(t, &scriptRunner{fail: map[string]error{"launchctl kickstart": errScript}}, &fakeStore{})
	if _, err := in.Install(context.Background()); !errors.Is(err, errScript) {
		t.Fatalf("a failed restart = %v", err)
	}
}

func TestFreeServiceID(t *testing.T) {
	if id, err := freeServiceID("", ""); err != nil || id != 300 {
		t.Fatalf("empty = %d, %v", id, err)
	}
	var b strings.Builder
	for i := 300; i <= 399; i++ {
		b.WriteString("x ")
		b.WriteString(strconv.Itoa(i))
		b.WriteString("\n")
	}
	if _, err := freeServiceID(b.String(), ""); err == nil {
		t.Fatal("a full range produced an id")
	}
	if id, _ := freeServiceID("garbage\nname notanumber\n", "g 300"); id != 301 {
		t.Fatalf("a taken group id = %d", id)
	}
}

func TestMacPlistsRunUnderTheServiceAccount(t *testing.T) {
	b, err := macospkg.Files.ReadFile("dev.keylatch.broker.plist")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		"<key>UserName</key>\n  <string>_keylatch</string>",
		"<key>Label</key>\n  <string>dev.keylatch.broker</string>",
		"<string>/usr/local/libexec/keylatch/keylatchd</string>",
		"<key>Umask</key>\n  <integer>63</integer>",
		"<key>Core</key>\n    <integer>0</integer>",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("broker plist lacks %q", want)
		}
	}
	for _, banned := range []string{"EnvironmentVariables", "KEYLATCH_", "<string>root</string>"} {
		if strings.Contains(s, banned) {
			t.Errorf("broker plist contains %q", banned)
		}
	}
	a, err := macospkg.Files.ReadFile("dev.keylatch.presence.plist")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(a), "UserName") || !strings.Contains(string(a), "LimitLoadToSessionType") {
		t.Error("the presence helper must run in the user's own session")
	}
}

func TestEnrollPresence(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	run := &scriptRunner{out: map[string]string{"launchctl asuser 501": string(pemOf(t, &k.PublicKey))}}
	path, err := EnrollPresence(context.Background(), run, func() int { return 0 }, state, 501)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(state, "presence", "501.pem") {
		t.Fatalf("path = %s", path)
	}
	if !run.called("launchctl asuser 501 /" + macPresenceApp + " public-key") {
		t.Fatalf("calls = %v", run.calls)
	}
	if _, err := (DirKeys{Dir: filepath.Join(state, "presence")}).PresenceKey(501); err != nil {
		t.Fatalf("the enrolled key does not load: %v", err)
	}
	if _, err := EnrollPresence(context.Background(), run, func() int { return 501 }, state, 501); !errors.Is(err, ErrNotRoot) {
		t.Fatalf("non-root = %v", err)
	}
	if _, err := EnrollPresence(context.Background(), &scriptRunner{fail: map[string]error{"launchctl": errScript}}, func() int { return 0 }, state, 501); err == nil {
		t.Fatal("a failing helper enrolled a key")
	}
	if _, err := EnrollPresence(context.Background(), &scriptRunner{out: map[string]string{"launchctl": "not a key"}}, func() int { return 0 }, state, 502); err == nil {
		t.Fatal("garbage enrolled as a key")
	}
	if len(MacUninstallCommands()) == 0 {
		t.Fatal("no uninstall commands")
	}
}
