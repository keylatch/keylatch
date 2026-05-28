package exec_test

import (
	"context"
	"runtime"
	"strings"
	"testing"

	kexec "github.com/keylatch/keylatch/internal/exec"
)

func TestResolve_optional_missing(t *testing.T) {
	got := kexec.Resolve("no-such-binary-xyz-keylatch-test")
	if got != "" {
		t.Errorf("Resolve: expected empty string, got %q", got)
	}
}

func TestMustResolve_panic(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Error("MustResolve: expected panic, got none")
		}
	}()
	kexec.MustResolve("no-such-binary-xyz-keylatch-test")
}

func TestRun_relative_path_rejected(t *testing.T) {
	ctx := context.Background()
	_, _, _, err := kexec.DefaultRunner.Run(ctx, "relative/bin", nil, nil)
	if err == nil {
		t.Fatal("Run: expected error for relative path, got nil")
	}
	if !strings.Contains(err.Error(), "relative path rejected") {
		t.Errorf("Run: error %q does not contain 'relative path rejected'", err.Error())
	}
}

func TestRun_stdin_pipe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("/bin/cat does not exist on Windows")
	}
	ctx := context.Background()
	stdin := []byte("hello")
	stdout, _, exitCode, err := kexec.DefaultRunner.Run(ctx, "/bin/cat", nil, stdin)
	if err != nil {
		t.Fatalf("Run /bin/cat: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code: got %d, want 0", exitCode)
	}
	if string(stdout) != "hello" {
		t.Errorf("stdout: got %q, want %q", stdout, "hello")
	}
}

func TestRun_exit_code(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("/usr/bin/false does not exist on Windows")
	}
	ctx := context.Background()
	_, _, exitCode, err := kexec.DefaultRunner.Run(ctx, "/usr/bin/false", nil, nil)
	if err != nil {
		t.Fatalf("Run /usr/bin/false: unexpected error: %v", err)
	}
	if exitCode == 0 {
		t.Error("exit code: expected non-zero, got 0")
	}
}

func TestRun_stdout_stderr_separated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("/bin/bash does not exist on Windows")
	}
	ctx := context.Background()
	// Use a shell script via bash to write to both stdout and stderr.
	stdout, stderr, exitCode, err := kexec.DefaultRunner.Run(ctx, "/bin/bash", []string{"-c", "echo out; echo err >&2"}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code: got %d, want 0", exitCode)
	}
	if !strings.Contains(string(stdout), "out") {
		t.Errorf("stdout: got %q, expected to contain 'out'", stdout)
	}
	if !strings.Contains(string(stderr), "err") {
		t.Errorf("stderr: got %q, expected to contain 'err'", stderr)
	}
}

func TestMockRunner_RecordsCalls(t *testing.T) {
	m := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			"/bin/echo|hello": {Stdout: []byte("hello\n"), ExitCode: 0},
		},
	}

	ctx := context.Background()
	stdout, _, code, err := m.Run(ctx, "/bin/echo", []string{"hello"}, nil)
	if err != nil {
		t.Fatalf("MockRunner.Run: %v", err)
	}
	if code != 0 {
		t.Errorf("exit code: %d", code)
	}
	if string(stdout) != "hello\n" {
		t.Errorf("stdout: got %q", stdout)
	}
	if len(m.Calls) != 1 {
		t.Errorf("Calls: got %d, want 1", len(m.Calls))
	}
	if m.Calls[0].Name != "/bin/echo" {
		t.Errorf("Call.Name: got %q", m.Calls[0].Name)
	}
}

func TestMockRunner_NoMatchReturnsZero(t *testing.T) {
	m := &kexec.MockRunner{}
	ctx := context.Background()
	stdout, stderr, code, err := m.Run(ctx, "/usr/bin/no-match", nil, nil)
	if err != nil || code != 0 || stdout != nil || stderr != nil {
		t.Errorf("no-match response: got (%v, %v, %d, %v), want (nil, nil, 0, nil)", stdout, stderr, code, err)
	}
}
