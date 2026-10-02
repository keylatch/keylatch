package trust

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestNewTrustCmd_MarkedExperimental verifies the group's Short/Long help
// text carries the H8 experimental disclaimer.
func TestNewTrustCmd_MarkedExperimental(t *testing.T) {
	cmd := newTrustCmd()
	if !strings.Contains(cmd.Short, "experimental") {
		t.Errorf("Short must mention experimental, got %q", cmd.Short)
	}
	if !strings.Contains(cmd.Long, "EXPERIMENTAL") {
		t.Errorf("Long must carry the EXPERIMENTAL disclaimer, got %q", cmd.Long)
	}
	if !strings.Contains(cmd.Long, "trust enroll") || !strings.Contains(cmd.Long, "trust approve") {
		t.Errorf("Long must name the non-functional commands, got %q", cmd.Long)
	}
	if cmd.PersistentPreRunE == nil {
		t.Fatal("expected PersistentPreRunE to print the upfront notice")
	}
}

// TestTrustGroup_HiddenState verifies only the genuinely dead subcommands
// (enroll, approve) are hidden — everything backed by real internal/trust
// code (list, doctor, challenge, revoke, allowlist) stays visible.
func TestTrustGroup_HiddenState(t *testing.T) {
	cases := []struct {
		name   string
		hidden bool
	}{
		{"list", false},
		{"doctor", false},
		{"enroll <type>", true},
		{"challenge", false},
		{"approve <challenge-id>", true},
		{"revoke <root-id>", false},
		{"allowlist", false},
	}

	root := newTrustCmd()
	for _, tc := range cases {
		found := false
		for _, sub := range root.Commands() {
			if sub.Use == tc.name {
				found = true
				if sub.Hidden != tc.hidden {
					t.Errorf("%s: Hidden=%v, want %v", tc.name, sub.Hidden, tc.hidden)
				}
			}
		}
		if !found {
			t.Errorf("subcommand %q not registered", tc.name)
		}
	}
}

// TestTrustGroup_UpfrontNotice verifies the PersistentPreRunE notice is
// printed for a real (non-stub) subcommand invocation, without needing to
// touch the os.Exit paths.
func TestTrustGroup_UpfrontNotice(t *testing.T) {
	root := newTrustCmd()
	var stderr bytes.Buffer
	root.SetErr(&stderr)
	root.SetOut(&bytes.Buffer{})
	root.SetArgs([]string{"list"})

	if err := root.Execute(); err != nil {
		t.Fatalf("trust list: %v", err)
	}
	if !strings.Contains(stderr.String(), "experimental command group") {
		t.Errorf("expected upfront experimental notice on stderr, got %q", stderr.String())
	}
}

// TestTrustList_Works is a control case proving `trust list` (one of the
// commands H8 says must remain functional) still runs cleanly.
func TestTrustList_Works(t *testing.T) {
	root := newTrustCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"list", "--json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("trust list --json: %v", err)
	}
	if !strings.Contains(stdout.String(), "[") {
		t.Errorf("expected JSON array output, got %q", stdout.String())
	}
}

// --- subprocess tests for the os.Exit(exitcode.NotImplemented) paths ---
//
// trustNotImplemented calls os.Exit directly (matching the file's existing
// convention for the LLM-session guard), so the only reliable way to assert
// its exit code is the standard Go re-exec-self pattern: re-invoke this same
// test binary in a child process that actually triggers the path, then
// assert on the child's exit code from the parent.

const reexecEnvVar = "KEYLATCH_TRUST_TEST_REEXEC"

// TestTrustEnroll_ExitsNotImplemented verifies `trust enroll secure-enclave`
// exits with exitcode.NotImplemented (10), not a generic error code.
func TestTrustEnroll_ExitsNotImplemented(t *testing.T) {
	runReexecCase(t, "enroll", "secure-enclave")
}

// TestTrustApprove_ExitsNotImplemented verifies `trust approve` exits with
// exitcode.NotImplemented (10) once past the (real) challenge-lookup step.
func TestTrustApprove_ExitsNotImplemented(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	if err := os.MkdirAll(dir+"/.keylatch/approvals", 0o700); err != nil {
		t.Fatalf("mkdir approvals: %v", err)
	}

	// Write a real, unexpired challenge so the RunE reaches the
	// not-implemented signing step rather than erroring earlier.
	root := newTrustCmd()
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"challenge"})
	if err := root.Execute(); err != nil {
		t.Fatalf("trust challenge: %v", err)
	}
	id := strings.TrimSpace(stdout.String())
	if id == "" {
		t.Fatal("trust challenge produced no ID")
	}

	runReexecCase(t, "approve", id)
}

// runReexecCase re-invokes the current test binary with
// KEYLATCH_TRUST_TEST_REEXEC set, running `trust <args...>` for real and
// letting it os.Exit. The parent asserts the child exited with
// exitcode.NotImplemented (10).
func runReexecCase(t *testing.T, args ...string) {
	t.Helper()

	if os.Getenv(reexecEnvVar) == "1" {
		// Child process: actually run the command; trustNotImplemented will
		// call os.Exit(10) here, terminating this process.
		root := newTrustCmd()
		root.SetArgs(args)
		_ = root.Execute()
		os.Exit(0) // only reached if the command did NOT hit the stub path
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	cmd := exec.Command(exe, "-test.run=^"+t.Name()+"$", "-test.v")
	cmd.Env = filteredEnvWithoutLLMSignals()
	cmd.Env = append(cmd.Env, reexecEnvVar+"=1")
	// Propagate HOME override from the caller (TestTrustApprove sets it via
	// t.Setenv, which filteredEnvWithoutLLMSignals below already captures
	// since it reads os.Environ() at call time).
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err = cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected child to exit non-zero via os.Exit, got err=%v stderr=%s", err, stderr.String())
	}
	if exitErr.ExitCode() != 10 {
		t.Errorf("expected exit code 10 (exitcode.NotImplemented), got %d (stderr: %s)", exitErr.ExitCode(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "not yet implemented") {
		t.Errorf("expected tracking message on stderr, got %q", stderr.String())
	}
}

// filteredEnvWithoutLLMSignals returns the current process environment with
// every llmcontext detection signal stripped, so the child process's own
// LLM-session guard (which would otherwise pre-empt with exit code 2) does
// not fire regardless of the environment this test suite itself runs under.
func filteredEnvWithoutLLMSignals() []string {
	blocked := map[string]bool{
		"CLAUDE_CODE":             true,
		"CODEX_ENV":               true,
		"CREDENTIALS_LLM_SESSION": true,
		"CURSOR_SESSION":          true,
		"AIDER_SESSION":           true,
		"GEMINI_SESSION":          true,
		"OPENCODE_SESSION":        true,
	}
	env := os.Environ()
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name = kv[:i]
		}
		if blocked[name] {
			continue
		}
		out = append(out, kv)
	}
	return out
}
