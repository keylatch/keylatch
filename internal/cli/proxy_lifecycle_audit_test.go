package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/gateway"
)

type cdRecorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *cdRecorder) Emit(_ context.Context, e audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (r *cdRecorder) snapshot() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Event(nil), r.events...)
}

type cdSyncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *cdSyncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *cdSyncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func cdWaitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestProxyUp_UnavailableBuildWritesNothing(t *testing.T) {
	dir := cdIsolate(t)
	port := freePort(t)
	r := cdExec(t, newProxyUpCmd(), nil, "--port="+strconv.Itoa(port))
	if r.e == nil || !strings.Contains(r.e.Error(), ErrProxyUnsupported.Error()) || caExitCode(r.e) != exitcode.RuntimeNotAvailable {
		t.Fatalf("err = %v", r.e)
	}
	for _, f := range []string{proxyPIDPathFromDir(dir), proxyStatePathFromDir(dir)} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Fatalf("%s must not be written when the proxy is unavailable", f)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("an unavailable proxy must not hold the port: %v", err)
	}
	_ = ln.Close()
}

func TestProxyDown_CorruptPIDFile(t *testing.T) {
	dir := cdIsolate(t)
	if err := os.WriteFile(proxyPIDPathFromDir(dir), []byte("not-a-pid"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := cdExec(t, newProxyDownCmd(), nil)
	if r.e == nil || !strings.Contains(r.e.Error(), "proxy down: read PID") {
		t.Fatalf("down: err = %v", r.e)
	}
}

func TestProxyDown_AuditsStaleAndSignalledStops(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX signals required")
	}
	t.Run("stale", func(t *testing.T) {
		dir := cdIsolate(t)
		if err := os.WriteFile(proxyPIDPathFromDir(dir), []byte("99999999\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := writeProxyState(proxyStatePathFromDir(dir), proxyState{PID: 99999999, Port: 1}); err != nil {
			t.Fatal(err)
		}
		rec := &cdRecorder{}
		cmd := newProxyDownCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(nil)
		if err := cmd.ExecuteContext(audit.WithEmitter(context.Background(), rec)); err != nil {
			t.Fatal(err)
		}
		evs := rec.snapshot()
		if len(evs) != 1 || evs[0].Action != "proxy.stopped" || evs[0].Extra["reason"] != "already-dead" || evs[0].Extra["pid"] != 99999999 {
			t.Fatalf("unexpected events %+v", evs)
		}
		if _, err := os.Stat(proxyStatePathFromDir(dir)); !os.IsNotExist(err) {
			t.Fatal("state file must be removed")
		}
	})
	t.Run("running", func(t *testing.T) {
		dir := cdIsolate(t)
		child, err := startSleepChild(t)
		if err != nil {
			t.Skip(err)
		}
		defer func() { _ = child.Kill() }()
		if err := gateway.WritePID(proxyPIDPathFromDir(dir), child.Pid); err != nil {
			t.Fatal(err)
		}
		rec := &cdRecorder{}
		cmd := newProxyDownCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(nil)
		if err := cmd.ExecuteContext(audit.WithEmitter(context.Background(), rec)); err != nil {
			t.Fatal(err)
		}
		evs := rec.snapshot()
		if len(evs) != 1 || evs[0].Extra["reason"] != "sigterm" || evs[0].Extra["pid"] != child.Pid {
			t.Fatalf("unexpected events %+v", evs)
		}
		if want := fmt.Sprintf("proxy: stopped (pid: %d, reason: sigterm)", child.Pid); !strings.Contains(out.String(), want) {
			t.Fatalf("output %q missing %q", out.String(), want)
		}
	})
}

func TestProxyStatus_UsesRecordedPort(t *testing.T) {
	dir := cdIsolate(t)
	if err := gateway.WritePID(proxyPIDPathFromDir(dir), os.Getpid()); err != nil {
		t.Fatal(err)
	}
	if err := writeProxyState(proxyStatePathFromDir(dir), proxyState{PID: os.Getpid(), Port: 9443}); err != nil {
		t.Fatal(err)
	}
	r := cdExec(t, newProxyStatusCmd(), nil)
	if r.e != nil || !strings.Contains(r.out, "address: 127.0.0.1:9443") {
		t.Fatalf("err=%v out=%q", r.e, r.out)
	}
}

func TestProxyStateFile_ErrorPaths(t *testing.T) {
	dir := t.TempDir()
	asDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(filepath.Join(asDir, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := readProxyState(asDir); err == nil || !strings.Contains(err.Error(), "proxy: read state") {
		t.Fatalf("read: %v", err)
	}
	if err := removeProxyState(asDir); err == nil || !strings.Contains(err.Error(), "proxy: remove state") {
		t.Fatalf("remove: %v", err)
	}
	if err := writeProxyState(asDir, proxyState{PID: 1, Port: 2}); err == nil || !strings.Contains(err.Error(), "rename state file") {
		t.Fatalf("write over dir: %v", err)
	}
	if _, err := os.Stat(asDir + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file must be removed after a failed rename")
	}
	if err := writeProxyState(filepath.Join(dir, "missing", "s"), proxyState{}); err == nil || !strings.Contains(err.Error(), "write state tmp") {
		t.Fatalf("write into missing dir: %v", err)
	}
}

func TestStartProxyWithGateway_UnavailableBuildReleasesNothing(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "proxy.pid")
	port := freePort(t)
	if _, err := startProxyWithGateway(context.Background(), port, pidPath); !errors.Is(err, ErrProxyUnsupported) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("PID file written for an unavailable proxy: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("port must stay free: %v", err)
	}
	_ = ln.Close()
}
