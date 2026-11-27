//go:build unix

package brokerd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

type fakeRunner struct {
	calls []string
	stdin map[string][]byte
	fail  map[string]error
}

func (f *fakeRunner) Run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, line)
	if f.stdin == nil {
		f.stdin = map[string][]byte{}
	}
	if stdin != nil {
		f.stdin[line] = append([]byte(nil), stdin...)
	}
	if name == "systemd-creds" {
		// The real command writes the sealed file; the fake writes a marker.
		if err := os.WriteFile(args[len(args)-1], []byte("sealed"), 0o600); err != nil {
			return nil, err
		}
	}
	for prefix, err := range f.fail {
		if strings.HasPrefix(line, prefix) {
			return nil, err
		}
	}
	return nil, nil
}

func packagedFiles() fstest.MapFS {
	return fstest.MapFS{
		"sysusers.d/keylatch.conf":   {Data: []byte("u keylatch\n")},
		"systemd/keylatchd.service":  {Data: []byte("[Service]\n")},
		"systemd/keylatchd.socket":   {Data: []byte("[Socket]\n")},
		"polkit/dev.keylatch.policy": {Data: []byte("<policyconfig/>\n")},
	}
}

func newInstaller(t *testing.T) (*Installer, *fakeRunner, string) {
	t.Helper()
	root := t.TempDir()
	r := &fakeRunner{}
	return &Installer{Root: root, Files: packagedFiles(), Run: r, Euid: func() int { return 0 }, Rand: bytes.NewReader(bytes.Repeat([]byte{7}, 64))}, r, root
}

func TestInstallPlacesFilesAndStartsTheSocket(t *testing.T) {
	in, r, root := newInstaller(t)
	res, err := in.Install(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{
		"usr/lib/sysusers.d/keylatch.conf",
		"etc/systemd/system/keylatchd.service",
		"etc/systemd/system/keylatchd.socket",
		"usr/share/polkit-1/actions/dev.keylatch.policy",
		"etc/keylatch/root.cred",
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Errorf("%s was not installed: %v", rel, err)
		}
	}
	if !res.RootCreated || len(res.Written) != 5 {
		t.Fatalf("result = %+v", res)
	}
	// The order matters: the user exists before the credential, the units are
	// known before the socket starts.
	want := []string{"systemd-sysusers", "systemd-creds encrypt --with-key=auto --name=keylatch-root -", "systemctl daemon-reload", "systemctl enable --now keylatchd.socket"}
	if len(r.calls) != len(want) {
		t.Fatalf("commands = %v", r.calls)
	}
	for i, w := range want {
		if !strings.HasPrefix(r.calls[i], w) {
			t.Errorf("command %d = %q, want prefix %q", i, r.calls[i], w)
		}
	}
	// The device root is 32 random bytes fed through stdin, never a file or argument.
	var fed []byte
	for line, b := range r.stdin {
		if strings.HasPrefix(line, "systemd-creds") {
			fed = b
		}
	}
	if !bytes.Equal(fed, bytes.Repeat([]byte{7}, 32)) {
		t.Fatalf("systemd-creds received %x", fed)
	}
	for _, c := range r.calls {
		if strings.Contains(c, "07070707") {
			t.Fatal("the root must not appear on a command line")
		}
	}
	if info, _ := os.Stat(filepath.Join(root, "etc/keylatch/root.cred")); info.Mode().Perm() != 0o600 {
		t.Fatalf("root.cred mode = %v", info.Mode().Perm())
	}
}

func TestInstallIsIdempotentAndKeepsTheRoot(t *testing.T) {
	in, r, root := newInstaller(t)
	if _, err := in.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	cred := filepath.Join(root, "etc/keylatch/root.cred")
	if err := os.WriteFile(cred, []byte("existing-root"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.calls = nil
	res, err := in.Install(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.RootCreated || len(res.Written) != 0 {
		t.Fatalf("second install wrote %+v", res)
	}
	if got, _ := os.ReadFile(cred); string(got) != "existing-root" {
		t.Fatal("an existing device root was replaced; that would orphan every wrapped key")
	}
	for _, c := range r.calls {
		if strings.HasPrefix(c, "systemd-creds") {
			t.Fatal("systemd-creds ran against an existing credential")
		}
	}
}

func TestInstallLeavesPackagedUnitsAlone(t *testing.T) {
	in, _, root := newInstaller(t)
	packaged := filepath.Join(root, "usr/lib/systemd/system")
	if err := os.MkdirAll(packaged, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"keylatchd.service", "keylatchd.socket"} {
		if err := os.WriteFile(filepath.Join(packaged, u), []byte("packaged"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res, err := in.Install(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/systemd/system/keylatchd.service")); err == nil {
		t.Fatal("a packaged unit was shadowed by a copy in /etc")
	}
	if len(res.Kept) < 2 {
		t.Fatalf("kept = %v", res.Kept)
	}
}

func TestInstallRefusals(t *testing.T) {
	in, _, _ := newInstaller(t)
	in.Euid = func() int { return 1000 }
	if _, err := in.Install(context.Background()); !errors.Is(err, ErrNotRoot) || !strings.Contains(err.Error(), "sudo keylatch broker install") {
		t.Fatalf("non-root install = %v", err)
	}

	for name, fail := range map[string]string{
		"systemd-sysusers": "create the keylatch system user",
		"systemd-creds":    "seal the device root",
		"systemctl enable": "start the broker socket",
		"systemctl daemon": "start the broker socket",
	} {
		in, r, root := newInstaller(t)
		r.fail = map[string]error{fail2prefix(name): errors.New("boom")}
		if _, err := in.Install(context.Background()); err == nil || !strings.Contains(err.Error(), fail) {
			t.Errorf("%s failing: %v", name, err)
		}
		if name == "systemd-creds" {
			if _, err := os.Stat(filepath.Join(root, "etc/keylatch/root.cred")); err == nil {
				t.Error("a failed seal left a credential file behind")
			}
		}
	}

	in, _, _ = newInstaller(t)
	in.Files = fstest.MapFS{}
	if _, err := in.Install(context.Background()); err == nil {
		t.Fatal("missing packaged files must fail")
	}
	in, _, _ = newInstaller(t)
	in.Rand = bytes.NewReader([]byte("short"))
	if _, err := in.Install(context.Background()); err == nil || !strings.Contains(err.Error(), "device root") {
		t.Fatalf("a short random source = %v", err)
	}
}

func fail2prefix(name string) string {
	switch name {
	case "systemctl enable":
		return "systemctl enable"
	case "systemctl daemon":
		return "systemctl daemon-reload"
	}
	return name
}

func TestExecRunner(t *testing.T) {
	out, err := ExecRunner{}.Run(context.Background(), []byte("hello"), "cat")
	if err != nil || string(out) != "hello" {
		t.Fatalf("cat = %q, %v", out, err)
	}
	if _, err := (ExecRunner{}).Run(context.Background(), nil, "false"); err == nil {
		t.Fatal("a failing command must report its error")
	}
}
