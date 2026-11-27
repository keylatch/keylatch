//go:build !windows

package gateway

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const scHelperEnv = "KEYLATCH_GATEWAY_SC_BLOCK"

func TestSCBlockingHelperProcess(t *testing.T) {
	if os.Getenv(scHelperEnv) != "1" {
		t.Skip("helper process only")
	}
	_, _ = os.Stdin.Read(make([]byte, 1))
	os.Exit(0)
}

func scStartHelper(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSCBlockingHelperProcess$")
	cmd.Env = append(os.Environ(), scHelperEnv+"=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	return cmd
}

func TestSendTerm_TerminatesLiveProcessAndRemovesPID(t *testing.T) {
	cmd := scStartHelper(t)
	pidPath := filepath.Join(t.TempDir(), "gateway.pid")
	if err := WritePID(pidPath, cmd.Process.Pid); err != nil {
		t.Fatal(err)
	}
	if pid, running := IsRunning(pidPath); !running || pid != cmd.Process.Pid {
		t.Fatalf("IsRunning = (%d,%v)", pid, running)
	}
	if err := SendTerm(pidPath); err != nil {
		t.Fatalf("SendTerm: %v", err)
	}
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("pid file not removed: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("expected signal exit, got %v", err)
		}
		ws, ok := ee.Sys().(syscall.WaitStatus)
		if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGTERM {
			t.Fatalf("exit status = %v", ee)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("helper did not exit after SIGTERM")
	}
}

func TestSendTerm_ExitedProcessReturnsErrorAndCleansUp(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	pidPath := filepath.Join(t.TempDir(), "gateway.pid")
	if err := WritePID(pidPath, cmd.Process.Pid); err != nil {
		t.Fatal(err)
	}
	err := SendTerm(pidPath)
	if err == nil || !strings.Contains(err.Error(), "terminate") {
		t.Fatalf("want terminate error, got %v", err)
	}
	if _, statErr := os.Stat(pidPath); !os.IsNotExist(statErr) {
		t.Fatalf("pid file should be removed: %v", statErr)
	}
}

func TestPIDFile_ErrorPaths(t *testing.T) {
	dir := t.TempDir()

	if err := WritePID(filepath.Join(dir, "missing", "gw.pid"), 1); err == nil || !strings.Contains(err.Error(), "write PID tmp") {
		t.Fatalf("WritePID into missing dir: %v", err)
	}

	asDir := filepath.Join(dir, "piddir")
	if err := os.MkdirAll(filepath.Join(asDir, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WritePID(asDir, 1); err == nil || !strings.Contains(err.Error(), "rename PID file") {
		t.Fatalf("WritePID over directory: %v", err)
	}
	if _, err := os.Stat(asDir + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("tmp file left behind: %v", err)
	}
	if _, err := ReadPID(asDir); err == nil || !strings.Contains(err.Error(), "read PID file") {
		t.Fatalf("ReadPID on directory: %v", err)
	}
	if err := SendTerm(asDir); err == nil {
		t.Fatal("SendTerm should surface read error")
	}
	if err := RemovePID(asDir); err == nil || !strings.Contains(err.Error(), "remove PID file") {
		t.Fatalf("RemovePID on non-empty directory: %v", err)
	}
	if err := RemovePID(filepath.Join(dir, "absent.pid")); err != nil {
		t.Fatalf("RemovePID missing file: %v", err)
	}
}
