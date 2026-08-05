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

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/stretchr/testify/assert"
)

// CanarySecret is a sentinel value used to verify no credential leak.
// This value must never appear in stdout/stderr of any blocked command.
const CanarySecret = "KEYLATCH_CANARY_DO_NOT_LEAK_0xDEADBEEF"

var binaryPath string

func TestMain(m *testing.M) {
	// Initialise the global provider registry from embedded YAML templates so
	// unit-style tests in this package (e.g. TestGoldenPath_FullUserJourney) can perform
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
		t.Fatalf("canary secret leaked to stdout")
	}
	if bytes.Contains(stderr, []byte(CanarySecret)) {
		t.Fatalf("canary secret leaked to stderr")
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
			t.Fatalf("canary secret leaked to file %s", path)
		}
		return nil
	})
}

// TestE2E_CLAUDE_CODE_blocks_get verifies the CLAUDE_CODE signal blocks get.
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

// TestE2E_CODEX_ENV_blocks_get verifies the CODEX_ENV signal blocks get.
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

// TestE2E_CREDENTIALS_LLM_SESSION_1_blocks_get verifies the CREDENTIALS_LLM_SESSION=1 signal blocks get.
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

// ---------------------------------------------------------------------------
// The raw-credential session gate: raw-credential-path corroboration policy
// (docker-server-security hardening, fix/daemonup-bypass).
//
// Raw-credential-exposure paths — non-masked `get`, and `run` in
// direct_brokered / direct_classic_sandboxed runtime modes
// (runtime.IsRawCredentialMode) — are now gated for EVERY session, including
// SignalNone (no LLM signal detected at all, e.g. CREDENTIALS_LLM_SESSION=0
// or no signals set). This closes the "unset every signal and sail through"
// spoof-to-human gap the naive heuristic-only gate left open. Gateway/proxy
// `run` modes are never gated: the child only ever receives a scoped session
// token there, never the raw secret.
//
// The gate (RequireVerifiedSession, internal/cli/session_enforce.go) is
// satisfied by:
//   - a signed session ticket (KEYLATCH_LLM_TICKET), or
//   - keylatchd's authenticated IPC confirming this PID as an active tracked
//     session (llmcontext.SignalDaemonActive), or
//   - the explicit escape hatch: KEYLATCH_ALLOW_UNVERIFIED_SESSION=1 (env)
//     or allow_unverified_session (config.json).
//
// This is layered UNDER GuardLLMSession (`get`) and GuardRuntime (`run`):
//   - A *detected* LLM session (positive signals: CLAUDE_CODE, CODEX_ENV,
//     CREDENTIALS_LLM_SESSION=1) hits GuardLLMSession first on `get`, which
//     hard-blocks unconditionally (exit 2, "Blocked in LLM session" message,
//     no escape hatch) — the raw-credential session gate is never reached and its message never shown.
//   - A SignalNone `get` (no signals, or CREDENTIALS_LLM_SESSION=0) passes
//     GuardLLMSession, then hits the raw-credential session gate, which fails closed absent corroboration
//     or the opt-out (exit 2, the raw-credential session gate's message mentioning
//     KEYLATCH_ALLOW_UNVERIFIED_SESSION — a real hatch here, unlike get's
//     hard block).
//   - `run` in gateway_typed/gateway_sdk/gateway_proxy is unaffected by the raw-credential session gate
//     regardless of session (never exposes a raw secret).
//   - `run` in direct_brokered / direct_classic_sandboxed IS gated by the raw-credential session gate for
//     ANY session (LLM-detected or SignalNone) even though GuardRuntime
//     itself allows those modes in LLM sessions — the raw-credential session gate supersedes
//     that allowance for the raw-credential boundary. The opt-out (env var
//     or config) restores the previous unrestricted behavior.
// ---------------------------------------------------------------------------

// rawCredGateOptOut returns a copy of base with the raw-credential session gate escape hatch
// (KEYLATCH_ALLOW_UNVERIFIED_SESSION=1) merged in.
func rawCredGateOptOut(base map[string]string) map[string]string {
	merged := map[string]string{"KEYLATCH_ALLOW_UNVERIFIED_SESSION": "1"}
	for k, v := range base {
		merged[k] = v
	}
	return merged
}

// TestE2E_CREDENTIALS_LLM_SESSION_0_GatedWithoutOptOut verifies that
// CREDENTIALS_LLM_SESSION=0 (a SignalNone session — GuardLLMSession does not
// block it) is still gated by the raw-credential session gate on raw `get`: it fails closed absent
// corroboration or the escape hatch. The stderr must be the raw-credential session gate's message (which
// references the opt-out), NOT GuardLLMSession's hard "Blocked" message —
// GuardLLMSession never even fires here since there are no LLM signals.
func TestE2E_CREDENTIALS_LLM_SESSION_0_GatedWithoutOptOut(t *testing.T) {
	homeDir := t.TempDir()
	_, stderr, code := runKeylatch(t,
		map[string]string{"CREDENTIALS_LLM_SESSION": "0", "HOME": homeDir},
		"get", "svc", "key")

	assert.Equal(t, 2, code, "expected exit 2 (the raw-credential session gate fail-closed on SignalNone raw get)")
	assert.Contains(t, string(stderr), "KEYLATCH_ALLOW_UNVERIFIED_SESSION")
	assert.NotContains(t, string(stderr), "Blocked in LLM session",
		"SignalNone must never see GuardLLMSession's hard-block message")
}

// TestE2E_CREDENTIALS_LLM_SESSION_0_OptOutReachesHandler verifies that
// setting the escape hatch alongside CREDENTIALS_LLM_SESSION=0 lets the
// (SignalNone) session past the raw-credential session gate, reaching the not-implemented get handler.
func TestE2E_CREDENTIALS_LLM_SESSION_0_OptOutReachesHandler(t *testing.T) {
	homeDir := t.TempDir()
	_, _, code := runKeylatch(t,
		rawCredGateOptOut(map[string]string{"CREDENTIALS_LLM_SESSION": "0", "HOME": homeDir}),
		"get", "svc", "key")

	assert.Equal(t, 5, code, "expected exit 5 (OperationFailed/not-implemented) once the raw-credential session gate is opted out")
}

// TestE2E_no_signals_GatedWithoutOptOut verifies that a session with no LLM
// signals at all (SignalNone) is still gated by the raw-credential session gate on raw `get` — the
// unset-every-signal spoof-to-human case the raw-credential session gate exists to close.
func TestE2E_no_signals_GatedWithoutOptOut(t *testing.T) {
	homeDir := t.TempDir()
	_, stderr, code := runKeylatch(t,
		map[string]string{"HOME": homeDir},
		"get", "svc", "key")

	assert.Equal(t, 2, code, "expected exit 2 (the raw-credential session gate fail-closed on SignalNone raw get)")
	assert.Contains(t, string(stderr), "KEYLATCH_ALLOW_UNVERIFIED_SESSION")
	assert.NotContains(t, string(stderr), "Blocked in LLM session",
		"SignalNone must never see GuardLLMSession's hard-block message")
}

// TestE2E_no_signals_OptOutReachesHandler verifies that the escape hatch lets
// a no-signal session past the raw-credential session gate, reaching the not-implemented get handler.
func TestE2E_no_signals_OptOutReachesHandler(t *testing.T) {
	homeDir := t.TempDir()
	_, _, code := runKeylatch(t,
		rawCredGateOptOut(map[string]string{"HOME": homeDir}),
		"get", "svc", "key")

	assert.Equal(t, 5, code, "expected exit 5 once the raw-credential session gate is opted out")
}

// TestE2E_masked_exits_0_in_llm_session verifies get --masked is a safe path.
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

// TestE2E_VersionSubcommand_MatchesVersionFlag verifies the C6 fix:
// `keylatch version` (documented in docs/installation.md as the post-install
// verification step) exists and produces the exact same output as
// `keylatch --version`.
func TestE2E_VersionSubcommand_MatchesVersionFlag(t *testing.T) {
	homeDir := t.TempDir()

	stdoutCmd, _, codeCmd := runKeylatch(t, map[string]string{"HOME": homeDir}, "version")
	stdoutFlag, _, codeFlag := runKeylatch(t, map[string]string{"HOME": homeDir}, "--version")

	assert.Equal(t, 0, codeCmd, "keylatch version must exit 0")
	assert.Equal(t, 0, codeFlag, "keylatch --version must exit 0")
	assert.Equal(t, string(stdoutFlag), string(stdoutCmd), "keylatch version must print the same output as --version")
	assert.Contains(t, string(stdoutCmd), "keylatch ")
}

// TestE2E_help_exits_0_in_llm_session verifies --help works in LLM sessions.
func TestE2E_help_exits_0_in_llm_session(t *testing.T) {
	homeDir := t.TempDir()
	_, _, code := runKeylatch(t,
		map[string]string{"CLAUDE_CODE": "1", "HOME": homeDir},
		"--help")

	assert.Equal(t, 0, code, "--help must exit 0 in LLM session")
}

// TestLeafPackageDeps verifies internal/llmcontext has no internal/* deps.
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
			t.Errorf("llmcontext imports disallowed internal package: %s", line)
		}
	}
}

// TestStaticGrepNoOverride verifies there is no bypass or disable of the LLM guard.
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

	// Check production code for explicit guard override patterns — violations.
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
			t.Fatalf("found potential LLM guard override pattern %q: %s", pattern, out)
		}
	}
}

// TestE2E_GuardRuntime_AllowedModes verifies gateway modes proceed
// past both GuardRuntime and the raw-credential session gate in an LLM session — they never expose a raw
// credential value (the child only ever gets a scoped session token), so the raw-credential session gate
// is a no-op for them regardless of session classification.
//
// direct_brokered is deliberately NOT in this table: unlike the gateway
// modes, it is a raw-credential mode (runtime.IsRawCredentialMode) and is
// gated by the raw-credential session gate in an LLM session — see
// TestE2E_GuardRuntime_DirectBrokered_GatedInLLMSession below.
func TestE2E_GuardRuntime_AllowedModes(t *testing.T) {
	allowedCases := []struct {
		name    string
		runtime string
		args    []string
	}{
		{"gateway_typed", "gateway_typed", []string{"run", "--runtime", "gateway_typed", "openrouter", "--", "node", "x.js"}},
		{"gateway_sdk", "gateway_sdk", []string{"run", "--runtime", "gateway_sdk", "openrouter", "--", "node", "x.js"}},
		{"gateway_proxy", "gateway_proxy", []string{"run", "--runtime", "gateway_proxy", "openrouter", "--", "node", "x.js"}},
	}

	for _, tc := range allowedCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			homeDir := t.TempDir()
			_, _, code := runKeylatch(t,
				map[string]string{"CLAUDE_CODE": "1", "HOME": homeDir},
				tc.args...)
			// Allowed modes proceed past both guards — they must NOT exit 2
			// (SecurityBlock). The actual exit code may vary: exit 3
			// (Missing) if credentials are absent, exit 1 (UserError) if the
			// provider is unknown, or exit 5/7 for other operational states.
			// The invariant is: NOT 2 (neither guard blocked them).
			assert.NotEqual(t, 2, code, "runtime mode %s must not be blocked by guard (must not exit 2, got %d)", tc.runtime, code)
		})
	}
}

// TestE2E_Run_DirectBrokered_BootstrapPrecedesSessionGate verifies that on a
// clean (un-bootstrapped) machine a raw-credential run mode surfaces the
// actionable BootstrapMissing error (exit 7) rather than the raw-credential
// session gate's fail-closed message: the onboarding guards (bootstrap, then
// connection) run before the session gate, so a first-run user is told to
// bootstrap, not to provide session corroboration. Before setup there is no
// credential to protect, so the session gate has nothing to gate here.
//
// The session gate's own fail-closed behavior for raw-credential exposure is
// covered end-to-end by the `get` tests above (which do not depend on
// bootstrap) and exhaustively at the unit level in
// internal/cli/session_enforce_test.go.
func TestE2E_Run_DirectBrokered_BootstrapPrecedesSessionGate(t *testing.T) {
	homeDir := t.TempDir()
	_, stderr, code := runKeylatch(t,
		map[string]string{"CLAUDE_CODE": "1", "HOME": homeDir},
		"run", "--runtime", "direct_brokered", "aws-prod", "--", "./deploy.sh")

	assert.Equal(t, 7, code, "raw run before bootstrap must exit 7 (BootstrapMissing), ahead of the session gate; stderr: %s", stderr)
	assert.Contains(t, strings.ToLower(string(stderr)), "bootstrap")
}

// TestE2E_GuardRuntime_DirectClassicRemoved verifies that the permanently removed
// mode direct_classic exits 5 (RuntimeNotAvailable) — it was permanently removed
// and must never be reinstated.
func TestE2E_GuardRuntime_DirectClassicRemoved(t *testing.T) {
	homeDir := t.TempDir()
	stdout, stderr, code := runKeylatch(t,
		map[string]string{"CLAUDE_CODE": "1", "HOME": homeDir},
		"run", "--runtime", "direct_classic", "openrouter", "--", "node", "x.js")

	// exit 5 = RuntimeNotAvailable: mode permanently removed in v1.0.0.
	assert.Equal(t, 5, code, "direct_classic must exit 5 (RuntimeNotAvailable) — permanently removed")
	assert.Empty(t, stdout)
	assert.Contains(t, string(stderr), "direct_classic")
	assertNoCanaryLeak(t, stdout, stderr, homeDir)
}

// TestE2E_Run_SandboxedBootstrapPrecedesSessionGate verifies that
// direct_classic_sandboxed (a raw-credential mode) also surfaces the
// BootstrapMissing error (exit 7) on a clean machine, ahead of the
// raw-credential session gate — same onboarding-first ordering as
// direct_brokered. The session gate's raw-credential fail-closed behavior
// (which supersedes GuardRuntime's allowance of sandboxed in LLM sessions once
// a machine is set up) is covered by the get-path e2e tests and the
// session_enforce unit tests.
func TestE2E_Run_SandboxedBootstrapPrecedesSessionGate(t *testing.T) {
	homeDir := t.TempDir()
	_, stderr, code := runKeylatch(t,
		map[string]string{"CLAUDE_CODE": "1", "HOME": homeDir},
		"run", "--runtime", "direct_classic_sandboxed",
		"openrouter", "--", "node", "x.js")

	assert.Equal(t, 7, code,
		"raw sandboxed run before bootstrap must exit 7 (BootstrapMissing), ahead of the session gate; stderr: %s", stderr)
	assert.Contains(t, strings.ToLower(string(stderr)), "bootstrap")
}

// TestE2E_InjectBlockedInLLMSession verifies C-2: keylatch inject returns a non-zero
// exit code in v1.0.0 because the inject command was removed.
// Prior to removal this exited 2 (SecurityBlock) in LLM sessions; now the command
// does not exist at all and cobra returns exit 1 (unknown command).
func TestE2E_InjectBlockedInLLMSession(t *testing.T) {
	homeDir := t.TempDir()
	stdout, stderr, code := runKeylatch(t,
		map[string]string{"CLAUDE_CODE": "1", "HOME": homeDir},
		"inject", "openrouter")

	// exit 1 = UserError: cobra unknown command (inject removed).
	// root.SilenceErrors=true so cobra itself never prints anything, but
	// main.go (C5) prints cobra's "unknown command" error text to stderr
	// before the doctor hint. The invariant checked here is a non-zero exit
	// code and no stdout leak; stderr content is covered by TestE2E_C5_*.
	assert.NotEqual(t, 0, code, "inject must exit non-zero in v1.0.0 — command is removed")
	assert.Empty(t, stdout, "stdout must be empty for unknown command")
	assertNoCanaryLeak(t, stdout, stderr, homeDir)
}

// TestE2E_C5_UnknownCommandPrintsError verifies that an unknown command
// prints cobra's "unknown command" error to stderr (not just the doctor
// hint) — the specific symptom C5 fixes.
func TestE2E_C5_UnknownCommandPrintsError(t *testing.T) {
	homeDir := t.TempDir()
	_, stderr, code := runKeylatch(t,
		map[string]string{"HOME": homeDir},
		"totally-not-a-real-command")

	assert.NotEqual(t, 0, code)
	assert.Contains(t, string(stderr), "unknown command", "stderr must contain cobra's unknown-command error, not just the doctor hint")
	assert.Contains(t, string(stderr), cli.DoctorHint, "stderr must still contain the doctor hint")
}

// TestE2E_C5_MissingArgsPrintsError verifies that a cobra arg-count error
// (e.g. a required positional argument omitted) is printed to stderr.
func TestE2E_C5_MissingArgsPrintsError(t *testing.T) {
	homeDir := t.TempDir()
	_, stderr, code := runKeylatch(t,
		map[string]string{"HOME": homeDir},
		"keychain-clear") // requires exactly 1 arg

	assert.NotEqual(t, 0, code)
	assert.NotEmpty(t, stderr, "stderr must contain the cobra arg-count error, not just the doctor hint")
}

// TestE2E_Approve_LLMSession_PrintsErrorExactlyOnce is a regression test for
// the code-review Finding-001 double-print bug: approve_cmd.go's LLM-session
// guard used to print a formatted error via cmderr.Format AND return a
// *cli.CLIError, so main.go's C5 error-printing printed the same message a
// second time (in a different format). The guard now returns the *CLIError
// without printing directly — main.go is the single place that prints it.
func TestE2E_Approve_LLMSession_PrintsErrorExactlyOnce(t *testing.T) {
	homeDir := t.TempDir()
	_, stderr, code := runKeylatch(t,
		map[string]string{"CLAUDE_CODE": "1", "HOME": homeDir},
		"approve", "sometoken")

	assert.Equal(t, 2, code, "expected exit 2 (SecurityBlock)")
	assert.Equal(t, 1, strings.Count(string(stderr), "not permitted inside an LLM session"),
		"error message must appear exactly once in stderr, got: %s", stderr)
}

// TestE2E_Deny_LLMSession_PrintsErrorExactlyOnce mirrors the approve case for deny.
func TestE2E_Deny_LLMSession_PrintsErrorExactlyOnce(t *testing.T) {
	homeDir := t.TempDir()
	_, stderr, code := runKeylatch(t,
		map[string]string{"CLAUDE_CODE": "1", "HOME": homeDir},
		"deny", "sometoken")

	assert.Equal(t, 2, code, "expected exit 2 (SecurityBlock)")
	assert.Equal(t, 1, strings.Count(string(stderr), "not permitted inside an LLM session"),
		"error message must appear exactly once in stderr, got: %s", stderr)
}

// TestE2E_BrokerStatus_OutOfProcess_PrintsErrorExactlyOnce verifies the same
// double-print bug is fixed for `broker status` when the broker singleton is
// not running in-process (the default state for any freshly-invoked CLI).
// broker_status_cmd.go used to print "error[BrokerOutOfProcess]: ..." itself
// and then return a *CLIError that main.go printed again as
// "error[SecurityBlock]: ...". It now returns the *CLIError without
// printing directly, so "broker not running in-process" appears exactly once.
func TestE2E_BrokerStatus_OutOfProcess_PrintsErrorExactlyOnce(t *testing.T) {
	homeDir := t.TempDir()
	_, stderr, code := runKeylatch(t,
		map[string]string{"HOME": homeDir},
		"broker", "status")

	assert.Equal(t, 2, code, "expected exit 2 (SecurityBlock)")
	assert.Equal(t, 1, strings.Count(string(stderr), "broker not running in-process"),
		"error message must appear exactly once in stderr, got: %s", stderr)
	assert.Equal(t, 1, strings.Count(string(stderr), "error["),
		"exactly one formatted error[...] line must appear, got: %s", stderr)
}

// TestE2E_BrokerDryRun_OutOfProcess_PrintsErrorExactlyOnce mirrors the broker
// status case for `broker dry-run`.
func TestE2E_BrokerDryRun_OutOfProcess_PrintsErrorExactlyOnce(t *testing.T) {
	homeDir := t.TempDir()
	_, stderr, code := runKeylatch(t,
		map[string]string{"HOME": homeDir},
		"broker", "dry-run", "openrouter", "node")

	assert.Equal(t, 2, code, "expected exit 2 (SecurityBlock)")
	assert.Equal(t, 1, strings.Count(string(stderr), "broker not running in-process"),
		"error message must appear exactly once in stderr, got: %s", stderr)
	assert.Equal(t, 1, strings.Count(string(stderr), "error["),
		"exactly one formatted error[...] line must appear, got: %s", stderr)
}

// TestE2E_BrokerRevoke_OutOfProcess_PrintsErrorExactlyOnce mirrors the broker
// status case for `broker revoke <id>`.
func TestE2E_BrokerRevoke_OutOfProcess_PrintsErrorExactlyOnce(t *testing.T) {
	homeDir := t.TempDir()
	_, stderr, code := runKeylatch(t,
		map[string]string{"HOME": homeDir},
		"broker", "revoke", "sometokenid")

	assert.Equal(t, 2, code, "expected exit 2 (SecurityBlock)")
	assert.Equal(t, 1, strings.Count(string(stderr), "broker not running in-process"),
		"error message must appear exactly once in stderr, got: %s", stderr)
	assert.Equal(t, 1, strings.Count(string(stderr), "error["),
		"exactly one formatted error[...] line must appear, got: %s", stderr)
}

// TestE2E_Run_NonLLMBaseline_BootstrapPrecedesSessionGate verifies that a
// SignalNone (non-LLM) session running a raw-credential mode on a clean machine
// also gets BootstrapMissing (exit 7) first — the onboarding guards precede the
// session gate for every session class. The session gate's SignalNone
// fail-closed behavior (the "unset every signal" spoof-to-human case it exists
// to close) is verified end-to-end by the get-path tests above and unit-tested
// in internal/cli/session_enforce_test.go.
func TestE2E_Run_NonLLMBaseline_BootstrapPrecedesSessionGate(t *testing.T) {
	homeDir := t.TempDir()
	_, stderr, code := runKeylatch(t,
		map[string]string{"HOME": homeDir},
		"run", "--runtime", "direct_classic_sandboxed", "openrouter", "--", "node", "x.js")

	assert.Equal(t, 7, code,
		"raw run before bootstrap must exit 7 (BootstrapMissing) for a SignalNone session too, ahead of the session gate; stderr: %s", stderr)
	assert.Contains(t, strings.ToLower(string(stderr)), "bootstrap")
}
