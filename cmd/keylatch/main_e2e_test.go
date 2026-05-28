package main_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/stretchr/testify/assert"
)

// CanarySecret is a sentinel value used to verify no credential leak.
// S0-1: this value must never appear in stdout/stderr of any blocked command.
const CanarySecret = "KEYLATCH_CANARY_DO_NOT_LEAK_0xDEADBEEF"

var binaryPath string

func TestMain(m *testing.M) {
	// Initialise the global provider registry from embedded YAML templates so
	// unit-style tests in this package (e.g. TestGoldenPath_Phase3) can perform
	// registry lookups without relying on PersistentPreRunE.
	if err := registry.InitFromConfig(context.Background(), func(key string) string {
		return os.Getenv(key)
	}); err != nil {
		fmt.Fprintf(os.Stderr, "cmd/keylatch TestMain: InitFromConfig: %v\n", err)
		os.Exit(1)
	}

	dir, err := os.MkdirTemp("", "keylatch-e2e-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "keylatch")
	// go build always appends .exe on Windows; match that here so exec.Command
	// receives the actual file path (Windows CreateProcess does not try .exe
	// extensions when given a full absolute path).
	if runtime.GOOS == "windows" {
		binaryPath += ".exe"
	}
	out, err := exec.Command("go", "build", "-buildvcs=false", "-o", binaryPath, "github.com/keylatch/keylatch/cmd/keylatch").CombinedOutput()
	if err != nil {
		panic("failed to build keylatch binary: " + err.Error() + "\n" + string(out))
	}

	os.Exit(m.Run())
}

func runKeylatch(t *testing.T, env map[string]string, args ...string) (stdout, stderr []byte, exitCode int) {
	t.Helper()
	cmd := exec.Command(binaryPath, args...)
	cmd.Env = os.Environ()
	// Strip signals and XDG vars that leak runner state into the isolated subprocess env.
	filtered := []string{}
	for _, e := range cmd.Env {
		if !strings.HasPrefix(e, "CLAUDE_CODE=") &&
			!strings.HasPrefix(e, "CODEX_ENV=") &&
			!strings.HasPrefix(e, "CREDENTIALS_LLM_SESSION=") &&
			!strings.HasPrefix(e, "XDG_CONFIG_HOME=") &&
			!strings.HasPrefix(e, "KEYLATCH_CONFIG_DIR=") {
			filtered = append(filtered, e)
		}
	}
	cmd.Env = filtered
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	// When HOME is overridden but KEYLATCH_CONFIG_DIR is not, pin it to
	// <homeDir>/.keylatch so path resolution is predictable on all platforms.
	if home, ok := env["HOME"]; ok {
		if _, hasDir := env["KEYLATCH_CONFIG_DIR"]; !hasDir {
			cmd.Env = append(cmd.Env, "KEYLATCH_CONFIG_DIR="+filepath.Join(home, ".keylatch"))
		}
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	stdout = stdoutBuf.Bytes()
	stderr = stderrBuf.Bytes()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
	}
	return
}

func assertNoCanaryLeak(t *testing.T, stdout, stderr []byte, homeDir string) {
	t.Helper()
	if bytes.Contains(stdout, []byte(CanarySecret)) {
		t.Fatalf("canary secret leaked to stdout (S0-1)")
	}
	if bytes.Contains(stderr, []byte(CanarySecret)) {
		t.Fatalf("canary secret leaked to stderr (S0-1)")
	}
	if homeDir == "" {
		return
	}
	// Walk homeDir for any file containing the canary
	_ = filepath.Walk(homeDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if bytes.Contains(data, []byte(CanarySecret)) {
			t.Fatalf("canary secret leaked to file %s (S0-1)", path)
		}
		return nil
	})
}

// TestE2E_CLAUDE_CODE_blocks_get verifies S0-1, S0-2, S0-4.
func TestE2E_CLAUDE_CODE_blocks_get(t *testing.T) {
	homeDir := t.TempDir()
	stdout, stderr, code := runKeylatch(t,
		map[string]string{"CLAUDE_CODE": "1", "HOME": homeDir},
		"get", "svc", "key")

	assert.Equal(t, 2, code, "expected exit code 2 (SecurityBlock)")
	assert.Empty(t, stdout, "stdout must be empty when blocked")
	assert.Contains(t, string(stderr), "Blocked")
	assertNoCanaryLeak(t, stdout, stderr, homeDir)
}

// TestE2E_CODEX_ENV_blocks_get verifies S0-2 for CODEX_ENV signal.
func TestE2E_CODEX_ENV_blocks_get(t *testing.T) {
	homeDir := t.TempDir()
	stdout, stderr, code := runKeylatch(t,
		map[string]string{"CODEX_ENV": "1", "HOME": homeDir},
		"get", "svc", "key")

	assert.Equal(t, 2, code)
	assert.Empty(t, stdout)
	assert.Contains(t, string(stderr), "Blocked")
	assertNoCanaryLeak(t, stdout, stderr, homeDir)
}

// TestE2E_CREDENTIALS_LLM_SESSION_1_blocks_get verifies S0-2 for CREDENTIALS_LLM_SESSION=1.
func TestE2E_CREDENTIALS_LLM_SESSION_1_blocks_get(t *testing.T) {
	homeDir := t.TempDir()
	stdout, stderr, code := runKeylatch(t,
		map[string]string{"CREDENTIALS_LLM_SESSION": "1", "HOME": homeDir},
		"get", "svc", "key")

	assert.Equal(t, 2, code)
	assert.Empty(t, stdout)
	assert.Contains(t, string(stderr), "Blocked")
	assertNoCanaryLeak(t, stdout, stderr, homeDir)
}

// TestE2E_CREDENTIALS_LLM_SESSION_0_no_block verifies S0-3: =0 must NOT block.
func TestE2E_CREDENTIALS_LLM_SESSION_0_no_block(t *testing.T) {
	homeDir := t.TempDir()
	_, _, code := runKeylatch(t,
		map[string]string{"CREDENTIALS_LLM_SESSION": "0", "HOME": homeDir},
		"get", "svc", "key")

	assert.Equal(t, 5, code, "expected exit code 5 (OperationFailed/not-implemented), not 2 (SecurityBlock)")
}

// TestE2E_no_signals_no_block verifies S0-5: unset signals never block.
func TestE2E_no_signals_no_block(t *testing.T) {
	homeDir := t.TempDir()
	_, _, code := runKeylatch(t,
		map[string]string{"HOME": homeDir},
		"get", "svc", "key")

	assert.Equal(t, 5, code, "expected exit code 5, not 2")
}

// TestE2E_masked_exits_0_in_llm_session verifies S0-5: get --masked is safe.
func TestE2E_masked_exits_0_in_llm_session(t *testing.T) {
	homeDir := t.TempDir()
	stdout, stderr, code := runKeylatch(t,
		map[string]string{"CLAUDE_CODE": "1", "HOME": homeDir},
		"get", "--masked", "foo", "bar")

	assert.Equal(t, 0, code, "get --masked must exit 0 in LLM session")
	assert.Contains(t, string(stdout), "****")
	assert.Empty(t, stderr)
	assertNoCanaryLeak(t, stdout, stderr, homeDir)
}

// TestE2E_help_exits_0_in_llm_session verifies --help works in LLM sessions.
func TestE2E_help_exits_0_in_llm_session(t *testing.T) {
	homeDir := t.TempDir()
	_, _, code := runKeylatch(t,
		map[string]string{"CLAUDE_CODE": "1", "HOME": homeDir},
		"--help")

	assert.Equal(t, 0, code, "--help must exit 0 in LLM session")
}

// TestLeafPackageDeps verifies S0-7 / SC0-12: internal/llmcontext has no internal/* deps.
func TestLeafPackageDeps(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/keylatch/keylatch/internal/llmcontext").Output()
	if err != nil {
		t.Fatalf("go list -deps failed: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "github.com/keylatch/keylatch/internal/") &&
			line != "github.com/keylatch/keylatch/internal/llmcontext" {
			t.Errorf("llmcontext imports disallowed internal package: %s (S0-7)", line)
		}
	}
}

// TestStaticGrepNoOverride verifies S0-3 / SC0-13: no bypass or disable of the LLM guard.
// The guard functions themselves are allowed to check !IsLLMSession (early-return for non-LLM),
// but no handler may have a flag or override that disables the guard.
func TestStaticGrepNoOverride(t *testing.T) {
	// Locate the module root relative to this test file using go env GOMOD.
	modBytes, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD failed: %v", err)
	}
	modRoot := filepath.Dir(strings.TrimSpace(string(modBytes)))

	// Collect non-test .go files under internal/ for grepping.
	// Test files are excluded to avoid matching strings in test harnesses.
	var goFiles []string
	_ = filepath.Walk(filepath.Join(modRoot, "internal"), func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() &&
			strings.HasSuffix(path, ".go") &&
			!strings.HasSuffix(path, "_test.go") {
			goFiles = append(goFiles, path)
		}
		return nil
	})

	// Check production code for explicit guard override patterns — S0-3 violations.
	overridePatterns := []string{
		`ALLOW_LLM_SESSION`,
		`DISABLE_LLM_GUARD`,
		`skipLLMGuard`,
		`forceAllowLLM`,
	}
	for _, pattern := range overridePatterns {
		args := append([]string{"-lE", pattern}, goFiles...)
		cmd := exec.Command("grep", args...)
		out, _ := cmd.CombinedOutput()
		if len(bytes.TrimSpace(out)) > 0 {
			t.Fatalf("found potential LLM guard override pattern %q (S0-3): %s", pattern, out)
		}
	}
}

// TestE2E_GuardRuntime_AllowedModes verifies SC0-14: allowed modes proceed past guard.
func TestE2E_GuardRuntime_AllowedModes(t *testing.T) {
	allowedCases := []struct {
		name    string
		runtime string
		args    []string
	}{
		{"gateway_typed", "gateway_typed", []string{"run", "--runtime", "gateway_typed", "openrouter", "--", "node", "x.js"}},
		{"gateway_sdk", "gateway_sdk", []string{"run", "--runtime", "gateway_sdk", "openrouter", "--", "node", "x.js"}},
		{"direct_brokered", "direct_brokered", []string{"run", "--runtime", "direct_brokered", "aws-prod", "--", "./deploy.sh"}},
		{"gateway_proxy", "gateway_proxy", []string{"run", "--runtime", "gateway_proxy", "openrouter", "--", "node", "x.js"}},
	}

	for _, tc := range allowedCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			homeDir := t.TempDir()
			_, _, code := runKeylatch(t,
				map[string]string{"CLAUDE_CODE": "1", "HOME": homeDir},
				tc.args...)
			// Allowed modes proceed past the guard — they must NOT exit 2 (SecurityBlock).
			// The actual exit code may vary: exit 3 (Missing) if credentials are absent,
			// exit 1 (UserError) if the provider is unknown, or exit 5 (OperationFailed).
			// The invariant is: NOT 2 (the guard did not block them).
			assert.NotEqual(t, 2, code, "runtime mode %s must not be blocked by guard (must not exit 2, got %d)", tc.runtime, code)
		})
	}
}

// TestE2E_GuardRuntime_DirectClassicRemoved verifies that the permanently removed
// mode direct_classic exits 5 (RuntimeNotAvailable) — it was removed in T-10-03
// and must never be reinstated.
func TestE2E_GuardRuntime_DirectClassicRemoved(t *testing.T) {
	homeDir := t.TempDir()
	stdout, stderr, code := runKeylatch(t,
		map[string]string{"CLAUDE_CODE": "1", "HOME": homeDir},
		"run", "--runtime", "direct_classic", "openrouter", "--", "node", "x.js")

	// exit 5 = RuntimeNotAvailable: mode permanently removed in v1.0.0 (T-10-03).
	assert.Equal(t, 5, code, "direct_classic must exit 5 (RuntimeNotAvailable) — permanently removed in T-10-03")
	assert.Empty(t, stdout)
	assert.Contains(t, string(stderr), "direct_classic")
	assertNoCanaryLeak(t, stdout, stderr, homeDir)
}

// TestE2E_GuardRuntime_SandboxedAllowedInLLMSession verifies that
// direct_classic_sandboxed is allowed in LLM sessions (EPIC-24 reinstated it).
// Without bootstrap the run will exit 7 (BootstrapMissing) — not 5 (removed)
// and not 2 (security block), proving the mode passes the guard.
func TestE2E_GuardRuntime_SandboxedAllowedInLLMSession(t *testing.T) {
	homeDir := t.TempDir()
	_, stderr, code := runKeylatch(t,
		map[string]string{"CLAUDE_CODE": "1", "HOME": homeDir},
		"run", "--runtime", "direct_classic_sandboxed",
		"openrouter", "--", "node", "x.js")

	// Must NOT be SecurityBlock (2) — the guard allows this mode in LLM sessions.
	// Must NOT be RuntimeNotAvailable (5) — the mode is active (EPIC-24), not removed.
	// Without bootstrap, the run exits 7 (BootstrapMissing).
	assert.NotEqual(t, 2, code,
		"direct_classic_sandboxed must not be security-blocked in LLM session (EPIC-24); stderr: %s", stderr)
	assert.NotEqual(t, 5, code,
		"direct_classic_sandboxed must not return RuntimeNotAvailable — mode is active (EPIC-24); stderr: %s", stderr)
}

// TestE2E_InjectBlockedInLLMSession verifies C-2: keylatch inject returns a non-zero
// exit code in v1.0.0 because the inject command was removed (T-10-02).
// Prior to T-10-02 this exited 2 (SecurityBlock) in LLM sessions; now the command
// does not exist at all and cobra returns exit 1 (unknown command).
func TestE2E_InjectBlockedInLLMSession(t *testing.T) {
	homeDir := t.TempDir()
	stdout, stderr, code := runKeylatch(t,
		map[string]string{"CLAUDE_CODE": "1", "HOME": homeDir},
		"inject", "openrouter")

	// exit 1 = UserError: cobra unknown command (inject removed in T-10-02).
	// SilenceErrors = true: cobra does not print the error text, main.go prints
	// the doctor hint only. The invariant is a non-zero exit code.
	assert.NotEqual(t, 0, code, "inject must exit non-zero in v1.0.0 — command is removed")
	assert.Empty(t, stdout, "stdout must be empty for unknown command")
	assertNoCanaryLeak(t, stdout, stderr, homeDir)
}

// TestE2E_GuardRuntime_NonLLMBaseline verifies non-LLM sessions are never blocked by GuardRuntime.
func TestE2E_GuardRuntime_NonLLMBaseline(t *testing.T) {
	homeDir := t.TempDir()
	_, _, code := runKeylatch(t,
		map[string]string{"HOME": homeDir},
		"run", "--runtime", "direct_classic_sandboxed", "openrouter", "--", "node", "x.js")

	// Non-LLM sessions must not be blocked by GuardRuntime (exit 2).
	// The command may exit with Missing (3) if credentials are absent,
	// or OperationFailed (5) for other errors — but never SecurityBlock (2) from guard.
	assert.NotEqual(t, 2, code, "non-LLM session must never be blocked by GuardRuntime (must not exit 2, got %d)", code)
}
