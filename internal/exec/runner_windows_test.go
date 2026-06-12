package exec_test

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	kexec "github.com/keylatch/keylatch/internal/exec"
)

// TestDefaultRunner_AbsolutePathCrossPlatform verifies Run accepts a real
// absolute path on every platform. Regression test for the "/"-prefix check
// that rejected all Windows absolute paths (C:\...), breaking op/bw/docker
// invocation on Windows.
func TestDefaultRunner_AbsolutePathCrossPlatform(t *testing.T) {
	t.Parallel()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go binary not in PATH")
	}

	stdout, _, exitCode, err := kexec.DefaultRunner.Run(context.Background(), goBin, []string{"version"}, nil)
	if err != nil {
		t.Fatalf("Run(%s version): %v", goBin, err)
	}
	if exitCode != 0 {
		t.Fatalf("exit code = %d", exitCode)
	}
	if !strings.Contains(string(stdout), "go version") {
		t.Errorf("unexpected stdout: %q", string(stdout))
	}
}

// TestDefaultRunner_NonZeroExitCrossPlatform covers the ExitError branch
// without unix-only binaries: `go unknown-subcommand` exits non-zero.
func TestDefaultRunner_NonZeroExitCrossPlatform(t *testing.T) {
	t.Parallel()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go binary not in PATH")
	}
	_, _, exitCode, err := kexec.DefaultRunner.Run(context.Background(), goBin, []string{"definitely-not-a-subcommand"}, nil)
	if err != nil {
		t.Fatalf("Run: unexpected transport error %v", err)
	}
	if exitCode == 0 {
		t.Error("expected non-zero exit code")
	}
}
