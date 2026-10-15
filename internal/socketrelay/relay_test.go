//go:build unix

package socketrelay

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func env(m map[string]string) Lookup { return func(k string) string { return m[k] } }

func listen(t *testing.T) (path string, ln *net.UnixListener) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "rl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path = filepath.Join(dir, "k.sock")
	ln, err = net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return path, ln
}

func TestSocketPath(t *testing.T) {
	t.Cleanup(func() { DefaultSocket = "" })
	if got := SocketPath(env(map[string]string{SocketEnv: "/x/s", "XDG_RUNTIME_DIR": "/run/u"})); got != "/x/s" {
		t.Errorf("override = %q", got)
	}
	if got := SocketPath(env(map[string]string{"XDG_RUNTIME_DIR": "/run/u"})); got != "/run/u/keylatch/keylatchd.sock" {
		t.Errorf("default = %q", got)
	}
	if got := SocketPath(env(nil)); !strings.HasSuffix(got, "/keylatchd.sock") {
		t.Errorf("fallback = %q", got)
	}
	DefaultSocket = "/opt/keylatch/s"
	if got := SocketPath(env(map[string]string{"XDG_RUNTIME_DIR": "/run/u"})); got != "/opt/keylatch/s" {
		t.Errorf("build-time default = %q", got)
	}
}

func TestRunForwardsBytesBothWays(t *testing.T) {
	path, ln := listen(t)
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		b, _ := io.ReadAll(c)
		got <- string(b)
		_, _ = c.Write([]byte("reply\n"))
	}()

	var out bytes.Buffer
	if err := Run(env(map[string]string{SocketEnv: path}), strings.NewReader(`{"op":"exec"}`+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	if req := <-got; req != `{"op":"exec"}`+"\n" {
		t.Errorf("daemon received %q", req)
	}
	if out.String() != "reply\n" {
		t.Errorf("caller received %q", out.String())
	}
}

func TestRunRefusesUnsafeSockets(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "rl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	path, _ := listen(t)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	loose := filepath.Join(dir, "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	looseSock := filepath.Join(loose, "k.sock")
	looseLn, err := net.ListenUnix("unix", &net.UnixAddr{Name: looseSock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = looseLn.Close() })
	stale := filepath.Join(dir, "stale.sock")
	staleLn, err := net.ListenUnix("unix", &net.UnixAddr{Name: stale, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	staleLn.SetUnlinkOnClose(false)
	_ = staleLn.Close()

	for name, p := range map[string]string{
		"missing":                 filepath.Join(dir, "none"),
		"not a socket":            regular,
		"symlink":                 link,
		"directory others write":  looseSock,
		"nobody is listening":     stale,
		"parent directory absent": "/nonexistent/dir/k.sock",
	} {
		var out bytes.Buffer
		if err := Run(env(map[string]string{SocketEnv: p}), strings.NewReader("x"), &out); err == nil {
			t.Errorf("%s: relay connected", name)
		}
		if out.Len() != 0 {
			t.Errorf("%s: relay wrote %q", name, out.String())
		}
	}
}

func TestCheckOwnedRejectsAnotherUser(t *testing.T) {
	path, _ := listen(t)
	if err := checkOwned(path, uint32(os.Getuid())); err != nil { //nolint:gosec // G115: uid is non-negative
		t.Fatalf("own socket refused: %v", err)
	}
	if err := checkOwned(path, uint32(os.Getuid())+1); err == nil { //nolint:gosec // G115: uid is non-negative
		t.Fatal("a socket owned by another user was accepted")
	}
}
