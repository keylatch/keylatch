package proc

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const helperEnv = "KEYLATCH_PROC_HARDEN_HELPER"

// TestMain doubles as the hardened child: it hardens itself, reports its
// readiness on stdout and waits for stdin to close.
func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "1" {
		if err := Harden(); err != nil {
			fmt.Println("harden-error:", err)
			os.Exit(1)
		}
		fmt.Println("ready")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// A hardened process is not dumpable and writes no core file.
func TestHardenClearsDumpableAndCoreLimit(t *testing.T) {
	if err := Harden(); err != nil {
		t.Fatal(err)
	}
	dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil || dumpable != 0 {
		t.Fatalf("dumpable = %d, err = %v", dumpable, err)
	}
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &lim); err != nil || lim.Cur != 0 || lim.Max != 0 {
		t.Fatalf("RLIMIT_CORE = %+v, err = %v", lim, err)
	}
}

// Another process of the same user cannot read the hardened process's
// environment or memory, and cannot attach a debugger to it.
func TestProcessNotDumpable(t *testing.T) {
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), helperEnv+"=1", "KEYLATCH_PROC_CANARY=synthetic-canary-value")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start a child process here: %v", err)
	}
	t.Cleanup(func() { _ = stdin.Close(); _ = cmd.Wait() })

	line := make(chan string, 1)
	go func() {
		s, _ := bufio.NewReader(stdout).ReadString('\n')
		line <- strings.TrimSpace(s)
	}()
	select {
	case got := <-line:
		if got != "ready" {
			t.Fatalf("helper said %q", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("helper did not become ready")
	}

	for _, name := range []string{"environ", "mem", "maps"} {
		f, err := os.Open(fmt.Sprintf("/proc/%d/%s", cmd.Process.Pid, name))
		if err == nil {
			_ = f.Close()
			t.Errorf("/proc/<pid>/%s is readable by the same user", name)
			continue
		}
		if !errors.Is(err, os.ErrPermission) {
			t.Errorf("/proc/<pid>/%s: %v, want permission denied", name, err)
		}
	}
	if err := unix.PtraceAttach(cmd.Process.Pid); err == nil {
		_ = unix.PtraceDetach(cmd.Process.Pid)
		t.Error("ptrace attach to the hardened process succeeded")
	} else if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
		t.Errorf("ptrace attach: %v, want EPERM", err)
	}
}
