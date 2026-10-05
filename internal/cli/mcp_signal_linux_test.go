//go:build linux

package cli

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ccStderrWatch redirects os.Stderr into a pipe and closes the returned
// channel once a line containing marker has been written.
func ccStderrWatch(t *testing.T, marker string) <-chan struct{} {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	old := os.Stderr
	os.Stderr = w
	seen := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(r)
		closed := false
		for sc.Scan() {
			if !closed && strings.Contains(sc.Text(), marker) {
				close(seen)
				closed = true
			}
		}
	}()
	t.Cleanup(func() {
		os.Stderr = old
		_ = w.Close()
	})
	return seen
}

// ccTermWhen sends SIGTERM to this process once ready fires, so the command's
// signal-aware context is cancelled exactly like an operator stopping it.
func ccTermWhen(t *testing.T, ready func() bool) <-chan struct{} {
	t.Helper()
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		deadline := time.Now().Add(10 * time.Second)
		for !ready() {
			if time.Now().After(deadline) {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
	}()
	return sent
}

func TestCCMCP_StdioStopsCleanlyOnSIGTERM(t *testing.T) {
	ccEnv(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = old
		_ = w.Close()
		_ = r.Close()
	})
	seen := ccStderrWatch(t, "keylatch mcp ready")
	sent := ccTermWhen(t, func() bool {
		select {
		case <-seen:
			return true
		default:
			return false
		}
	})

	_, errOut, err := ccRun(t, "", "mcp")
	<-sent
	if err != nil {
		t.Fatalf("mcp returned %v (%s)", err, errOut)
	}
	if errOut != "" {
		t.Fatalf("clean shutdown wrote to command stderr: %q", errOut)
	}
}

func TestCCMCP_PortListensOnUnixSocketUntilSIGTERM(t *testing.T) {
	ccEnv(t)
	runtimeDir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	sock := filepath.Join(runtimeDir, "keylatch", "mcp.sock")
	ccStderrWatch(t, "never")

	sent := ccTermWhen(t, func() bool {
		_, err := os.Stat(sock)
		return err == nil
	})
	// The accept loop only observes cancellation between connections, so keep
	// dialling after the signal until the command has returned.
	done := make(chan struct{})
	go func() {
		<-sent
		for {
			select {
			case <-done:
				return
			default:
			}
			if conn, err := net.Dial("unix", sock); err == nil {
				_ = conn.Close()
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	_, errOut, err := ccRun(t, "", "mcp", "--port", "17999")
	close(done)
	if err != nil {
		t.Fatalf("mcp --port returned %v (%s)", err, errOut)
	}
	info, statErr := os.Stat(filepath.Dir(sock))
	if statErr != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("socket dir mode = %v, %v", info.Mode().Perm(), statErr)
	}
}
