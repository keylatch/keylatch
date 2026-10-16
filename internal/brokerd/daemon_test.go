//go:build unix

package brokerd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/keylatch/keylatch/internal/brokerd/keys"
)

func runOptions(t *testing.T) (Options, *bytes.Buffer) {
	t.Helper()
	creds := t.TempDir()
	if err := os.WriteFile(filepath.Join(creds, keys.CredentialName), bytes.Repeat([]byte{5}, 48), 0o600); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	return Options{
		Version:   "test",
		StateRoot: t.TempDir(),
		Socket:    filepath.Join(t.TempDir(), "broker.sock"),
		Env:       envOf(map[string]string{"CREDENTIALS_DIRECTORY": creds}),
		// An explicit loader keeps macOS from reaching for the System keychain.
		Root:     func() ([]byte, error) { return keys.LoadRoot(creds) },
		PID:      os.Getpid(),
		Harden:   func() error { return nil },
		Presence: &fakePresence{},
		Out:      out,
	}, out
}

func TestRunRefusesToStartUnprotected(t *testing.T) {
	o, _ := runOptions(t)
	o.Harden = func() error { return errors.New("prctl denied") }
	if err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "hardened") {
		t.Fatalf("an unhardenable process = %v", err)
	}

	o, _ = runOptions(t)
	o.Env = envOf(nil)
	o.Root = func() ([]byte, error) { return keys.LoadRoot("") }
	if err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "broker install") {
		t.Fatalf("no device root = %v", err)
	}

	o, _ = runOptions(t)
	o.RequireLock = true
	o.StateRoot = filepath.Join(os.DevNull, "state")
	if err := Run(context.Background(), o); err == nil {
		t.Fatal("an unusable state directory must stop the daemon")
	}

	// A hierarchy that opens but an audit log that cannot: the daemon does not serve.
	o, _ = runOptions(t)
	if err := os.MkdirAll(filepath.Join(o.StateRoot, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(o.StateRoot, "audit"), []byte("a file where the directory belongs"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "audit") {
		t.Fatalf("an unusable audit log = %v", err)
	}
}

func TestRunServesTheActivatedSocket(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("socket activation is a systemd (Linux) mechanism")
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("socket pairs are not permitted here: %v", err)
	}
	defer func() { _ = syscall.Close(fds[1]) }()
	prev := firstListenFD
	firstListenFD = uintptr(fds[0])
	defer func() { firstListenFD = prev }()

	o, out := runOptions(t)
	env := map[string]string{"LISTEN_PID": strconv.Itoa(os.Getpid()), "LISTEN_FDS": "1"}
	creds := o.Env("CREDENTIALS_DIRECTORY")
	env["CREDENTIALS_DIRECTORY"] = creds
	o.Env = envOf(env)

	// The device root's location and the activation variables must not reach the
	// verbs the daemon runs.
	var unset []string
	o.Unsetenv = func(name string) error { unset = append(unset, name); return nil }

	// The adopted descriptor is a connected socket, so accepting on it fails at
	// once; reaching that point means every earlier step succeeded.
	err = Run(context.Background(), o)
	for _, want := range []string{"CREDENTIALS_DIRECTORY", "LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		if !slices.Contains(unset, want) {
			t.Errorf("%s was left in the daemon's environment: unset %v", want, unset)
		}
	}
	if err == nil {
		t.Fatal("Serve on a connected socket must fail")
	}
	if !strings.Contains(out.String(), "broker serving on") {
		t.Fatalf("output = %q, err = %v", out.String(), err)
	}
	for _, d := range []string{"keys", "audit"} {
		if _, err := os.Stat(filepath.Join(o.StateRoot, d)); err != nil {
			t.Errorf("%s was not created: %v", d, err)
		}
	}
	if _, err := os.Stat(filepath.Join(o.StateRoot, "audit", "audit.log")); err != nil {
		t.Errorf("the audit log was not opened: %v", err)
	}

	// Restart resumes: the same state opens again with the same root.
	prevFD := firstListenFD
	fds2, _ := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	defer func() { _ = syscall.Close(fds2[1]) }()
	firstListenFD = uintptr(fds2[0])
	defer func() { firstListenFD = prevFD }()
	if err := Run(context.Background(), o); err == nil || !strings.Contains(out.String(), "broker serving on") {
		t.Fatalf("restart: %v", err)
	}
}

func TestRunWarnsWithoutAPresenceMethod(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("socket activation is a systemd (Linux) mechanism")
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("socket pairs are not permitted here: %v", err)
	}
	defer func() { _ = syscall.Close(fds[1]) }()
	prev := firstListenFD
	firstListenFD = uintptr(fds[0])
	defer func() { firstListenFD = prev }()

	o, out := runOptions(t)
	o.Presence = nil
	if NewPolkit() != nil {
		t.Skip("polkit is installed on this host")
	}
	env := map[string]string{"LISTEN_PID": strconv.Itoa(os.Getpid()), "LISTEN_FDS": "1", "CREDENTIALS_DIRECTORY": o.Env("CREDENTIALS_DIRECTORY")}
	o.Env = envOf(env)
	_ = Run(context.Background(), o)
	if !strings.Contains(out.String(), "no presence method") {
		t.Fatalf("output = %q", out.String())
	}
}
