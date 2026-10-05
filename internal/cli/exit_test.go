package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/spf13/cobra"
)

func TestReportError(t *testing.T) {
	plain := errors.New("gateway up: read signing key: permission denied")
	cases := []struct {
		name       string
		err        error
		wantCode   int
		wantStderr string
	}{
		{"nil", nil, 0, ""},
		{"plain error", plain, exitcode.UserError, "Error: " + plain.Error() + "\n"},
		{"wrapped error", fmt.Errorf("outer: %w", plain), exitcode.UserError, "Error: outer: " + plain.Error() + "\n"},
		{"cli error", NewSecurityBlock("blocked here"), exitcode.SecurityBlock, "error[SecurityBlock]: blocked here\n"},
		{"wrapped cli error", fmt.Errorf("ctx: %w", NewSecurityBlock("blocked here")), exitcode.SecurityBlock, "error[SecurityBlock]: blocked here\n"},
		{"reported", reported(exitcode.BackendUnavailable, nil), exitcode.BackendUnavailable, ""},
		{"reported with cause", reported(exitcode.UserError, plain), exitcode.UserError, ""},
		{"wrapped reported", fmt.Errorf("ctx: %w", reported(exitcode.SecurityBlock, nil)), exitcode.SecurityBlock, ""},
		{"cli error with zero code", &CLIError{Class: "X", Message: "m"}, exitcode.UserError, "error[X]: m\n"},
		{"coded error", withExitCode(exitcode.OperationFailed, plain), exitcode.OperationFailed, "Error: " + plain.Error() + "\n"},
		{"wrapped coded error", fmt.Errorf("ctx: %w", withExitCode(exitcode.OperationFailed, plain)), exitcode.OperationFailed, "Error: ctx: " + plain.Error() + "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			got := ReportError(&cobra.Command{Use: "doctor"}, []string{"doctor"}, tc.err, &stderr)
			if got != tc.wantCode {
				t.Fatalf("exit code = %d, want %d", got, tc.wantCode)
			}
			if stderr.String() != tc.wantStderr {
				t.Fatalf("stderr = %q, want %q", stderr.String(), tc.wantStderr)
			}
		})
	}
}

func TestReportErrorKeepsCauseReachable(t *testing.T) {
	err := reported(exitcode.BackendUnavailable, backend.ErrLocked)
	if !errors.Is(err, backend.ErrLocked) {
		t.Fatal("reported error hides its cause")
	}
}

func TestReportErrorAddsDoctorHint(t *testing.T) {
	root := NewRootCommand()
	var stderr bytes.Buffer
	code := ReportError(root, []string{"list"}, errors.New("boom"), &stderr)
	if code != exitcode.UserError {
		t.Fatalf("exit code = %d", code)
	}
	if want := "Error: boom\n" + DoctorHint + "\n"; stderr.String() != want {
		t.Fatalf("stderr = %q, want %q", stderr.String(), want)
	}
}

func TestReportErrorQuietCLIErrorPrintsNothing(t *testing.T) {
	var stderr bytes.Buffer
	code := ReportError(NewRootCommand(), []string{"launch"}, &CLIError{Class: "AgentExit", Code: 7, Message: "exit status 7", Quiet: true}, &stderr)
	if code != 7 {
		t.Fatalf("exit code = %d, want 7", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("quiet error printed %q", stderr.String())
	}
}

// executeAndReport runs args through a fresh root command the way main does
// and returns the exit code and everything written to stderr.
func executeAndReport(t *testing.T, args ...string) (int, string) {
	t.Helper()
	root := NewRootCommand()
	var stderr bytes.Buffer
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&stderr)
	root.SetIn(strings.NewReader(""))
	root.SetArgs(args)
	code := ReportError(root, args, root.Execute(), &stderr)
	return code, stderr.String()
}

func TestReportErrorPrintsCobraErrorOnce(t *testing.T) {
	code, stderr := executeAndReport(t, "no-such-command")
	if code != exitcode.UserError {
		t.Fatalf("exit code = %d", code)
	}
	if n := strings.Count(stderr, `unknown command "no-such-command"`); n != 1 {
		t.Fatalf("cobra error printed %d times:\n%s", n, stderr)
	}
}

func TestGatewayUpReportsInvalidSigningKey(t *testing.T) {
	testutil.ClearLLMSessionEnv(t)
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)
	t.Setenv("KEYLATCH_GATEWAY_PID", filepath.Join(dir, "gateway.pid"))
	keyPath := filepath.Join(dir, "signing.key")
	t.Setenv("KEYLATCH_GATEWAY_SIGNING_KEY", keyPath)
	if err := os.WriteFile(keyPath, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, stderr := executeAndReport(t, "gateway", "up")
	if code == 0 {
		t.Fatal("gateway up succeeded with an invalid signing key")
	}
	if n := strings.Count(stderr, "signing key must be 32 bytes"); n != 1 {
		t.Fatalf("signing key error printed %d times:\n%s", n, stderr)
	}

	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	code, stderr = executeAndReport(t, "gateway", "up")
	if code == 0 || strings.Count(stderr, "read signing key") != 1 {
		t.Fatalf("missing signing key: exit %d, stderr:\n%s", code, stderr)
	}
}

func TestBackendCommandsExitWithTheirCodeAndPrintOnce(t *testing.T) {
	testutil.ClearLLMSessionEnv(t)
	t.Setenv("KEYLATCH_CONFIG_DIR", t.TempDir())

	t.Run("bw unlock without a terminal", func(t *testing.T) {
		if stdinIsTTY() {
			t.Skip("stdin is a terminal")
		}
		code, stderr := executeAndReport(t, "bw", "unlock")
		requireReportedOnce(t, code, exitcode.UserError, stderr)
	})

	t.Run("bw unlock in an agent session", func(t *testing.T) {
		t.Setenv("CLAUDECODE", "1")
		code, stderr := executeAndReport(t, "bw", "unlock")
		requireReportedOnce(t, code, exitcode.SecurityBlock, stderr)
	})

	t.Run("op signin without the op CLI", func(t *testing.T) {
		root := NewRootCommand()
		var stderr bytes.Buffer
		root.SetErr(&stderr)
		err := runOPSignin(context.Background(), root, func(string) string { return "" }, nil, "", false)
		code := ReportError(root, []string{"op", "signin"}, err, &stderr)
		requireReportedOnce(t, code, exitcode.BackendUnavailable, stderr.String())
	})
}

func requireReportedOnce(t *testing.T, code, want int, stderr string) {
	t.Helper()
	if code != want {
		t.Fatalf("exit code = %d, want %d\n%s", code, want, stderr)
	}
	if n := strings.Count(stderr, "Error:"); n != 1 {
		t.Fatalf("%d error lines, want 1:\n%s", n, stderr)
	}
}
