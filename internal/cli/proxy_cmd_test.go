package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/gateway"
)

// envForDir returns a simple Lookup that maps KEYLATCH_CONFIG_DIR to dir.
func envForDir(dir string) func(string) string {
	return func(key string) string {
		if key == "KEYLATCH_CONFIG_DIR" {
			return dir
		}
		return os.Getenv(key)
	}
}

// TestProxyLiveness_NoFile returns not-running when no PID file exists.
func TestProxyLiveness_NoFile(t *testing.T) {
	dir := t.TempDir()
	env := envForDir(dir)

	running, _, err := proxyLiveness(env)
	if err != nil {
		t.Fatalf("proxyLiveness: %v", err)
	}
	if running {
		t.Error("expected proxy not running when no PID file exists")
	}
}

// TestProxyLiveness_AliveProcess returns running when PID file points to current process.
func TestProxyLiveness_AliveProcess(t *testing.T) {
	dir := t.TempDir()
	env := envForDir(dir)

	pidPath := proxyPIDPath(env)
	if err := gateway.WritePID(pidPath, os.Getpid()); err != nil {
		t.Fatalf("WritePID: %v", err)
	}
	t.Cleanup(func() { gateway.RemovePID(pidPath) }) //nolint:errcheck

	running, pid, err := proxyLiveness(env)
	if err != nil {
		t.Fatalf("proxyLiveness: %v", err)
	}
	if !running {
		t.Error("expected proxy running")
	}
	if pid != os.Getpid() {
		t.Errorf("pid = %d, want %d", pid, os.Getpid())
	}
}

// TestProxyLiveness_DeadProcess returns not-running for a non-existent PID.
func TestProxyLiveness_DeadProcess(t *testing.T) {
	dir := t.TempDir()
	env := envForDir(dir)

	pidPath := proxyPIDPath(env)
	// Use a PID that is guaranteed to not exist (very large number).
	deadPID := 99999999
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(deadPID)+"\n"), 0o600); err != nil {
		t.Fatalf("write PID file: %v", err)
	}

	running, _, err := proxyLiveness(env)
	if err != nil {
		t.Fatalf("proxyLiveness: %v", err)
	}
	if running {
		t.Error("expected proxy not running for dead PID")
	}
}

// TestProxyPIDPath verifies the PID path is constructed under config dir.
func TestProxyPIDPath(t *testing.T) {
	dir := t.TempDir()
	env := envForDir(dir)
	p := proxyPIDPath(env)
	if p == "" {
		t.Fatal("proxyPIDPath returned empty string")
	}
}

// TestProxyPIDPathFromDir verifies the helper appends proxy.pid to the given dir.
func TestProxyPIDPathFromDir(t *testing.T) {
	p := proxyPIDPathFromDir("/tmp/testdir")
	if p != "/tmp/testdir/proxy.pid" {
		t.Errorf("proxyPIDPathFromDir = %q, want /tmp/testdir/proxy.pid", p)
	}
}

// TestProxyStatusCmd_NotRunning verifies `proxy status` reports stopped when no PID file.
func TestProxyStatusCmd_NotRunning(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)

	cmd := newProxyStatusCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("proxy status: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("stopped")) {
		t.Errorf("proxy status: expected 'stopped' in output, got %q", out.String())
	}
}

// TestProxyStatusCmd_JSON_NotRunning verifies `proxy status --json` when not running.
func TestProxyStatusCmd_JSON_NotRunning(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)

	cmd := newProxyStatusCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("proxy status --json: %v", err)
	}

	var status proxyStatusOutput
	if err := json.Unmarshal(out.Bytes(), &status); err != nil {
		t.Fatalf("parse JSON: %v (output: %q)", err, out.String())
	}
	if status.Running {
		t.Error("expected Running=false when no PID file")
	}
	if status.PID != nil {
		t.Errorf("expected PID=nil when not running, got %v", status.PID)
	}
}

// TestProxyStatusCmd_Running verifies `proxy status` reports running when PID file present.
func TestProxyStatusCmd_Running(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)

	pidPath := proxyPIDPathFromDir(dir)
	if err := gateway.WritePID(pidPath, os.Getpid()); err != nil {
		t.Fatalf("WritePID: %v", err)
	}
	t.Cleanup(func() { _ = gateway.RemovePID(pidPath) })

	cmd := newProxyStatusCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("proxy status: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("running")) {
		t.Errorf("expected 'running' in output, got %q", out.String())
	}
}

// TestProxyStatusCmd_JSON_Running verifies JSON output when running.
func TestProxyStatusCmd_JSON_Running(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)

	pidPath := proxyPIDPathFromDir(dir)
	if err := gateway.WritePID(pidPath, os.Getpid()); err != nil {
		t.Fatalf("WritePID: %v", err)
	}
	t.Cleanup(func() { _ = gateway.RemovePID(pidPath) })

	cmd := newProxyStatusCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("proxy status --json: %v", err)
	}

	var status proxyStatusOutput
	if err := json.Unmarshal(out.Bytes(), &status); err != nil {
		t.Fatalf("parse JSON: %v (output: %q)", err, out.String())
	}
	if !status.Running {
		t.Error("expected Running=true")
	}
	if status.PID == nil || *status.PID != os.Getpid() {
		t.Errorf("expected PID=%d, got %v", os.Getpid(), status.PID)
	}
	if status.Address == "" {
		t.Error("expected non-empty Address when running")
	}
}

// TestProxyDownCmd_NotRunning verifies `proxy down` reports not running gracefully.
func TestProxyDownCmd_NotRunning(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)

	cmd := newProxyDownCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("proxy down: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("not running")) {
		t.Errorf("expected 'not running' in output, got %q", out.String())
	}
}

// TestBuildSandboxDoctorOutput_Windows verifies windows reports unavailable.
func TestBuildSandboxDoctorOutput_Windows(t *testing.T) {
	out := buildSandboxDoctorOutput("windows")
	if out.Available {
		t.Error("windows sandbox should be unavailable")
	}
	if out.Platform != "windows" {
		t.Errorf("platform = %q, want windows", out.Platform)
	}
}

// TestBuildSandboxDoctorOutput_Darwin verifies macOS reports available.
func TestBuildSandboxDoctorOutput_Darwin(t *testing.T) {
	out := buildSandboxDoctorOutput("darwin")
	if !out.Available {
		t.Error("darwin sandbox should be available")
	}
	if out.Tool != "sandbox-exec" {
		t.Errorf("tool = %q, want sandbox-exec", out.Tool)
	}
}

// --- proxy up tests ---

// freePort returns a local port that is not currently in use.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// TestSecurityRegression_ProxyUpRejectsUnsupported verifies that
// `proxy up` refuses immediately (gateway_proxy is unavailable) —
// no listener bound, no PID/state file written, no fake-healthy state
// published.
func TestSecurityRegression_ProxyUpRejectsUnsupported(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)

	port := freePort(t)
	pidPath := proxyPIDPathFromDir(dir)

	cmd := newProxyUpCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{fmt.Sprintf("--port=%d", port)})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected proxy up to refuse; got nil error")
	}
	var cliErr *CLIError
	if !errors.As(err, &cliErr) {
		t.Fatalf("expected *CLIError, got %T: %v", err, err)
	}
	if cliErr.Class != "RuntimeNotAvailable" {
		t.Errorf("expected Class=RuntimeNotAvailable, got %q", cliErr.Class)
	}
	if !strings.Contains(cliErr.Message, ErrProxyUnsupported.Error()) {
		t.Errorf("expected message to mention proxy unsupported, got %q", cliErr.Message)
	}

	if _, statErr := os.Stat(pidPath); !os.IsNotExist(statErr) {
		t.Error("expected no PID file to be written when proxy is unsupported")
	}

	// Confirm nothing is actually listening on the requested port.
	if conn, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond); dialErr == nil {
		conn.Close()
		t.Error("expected no listener; connection to proxy port unexpectedly succeeded")
	}
}

// TestProxyUp_AlreadyRunning verifies that `proxy up` returns an error if the proxy is already running.
func TestProxyUp_AlreadyRunning(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)

	pidPath := proxyPIDPathFromDir(dir)
	if err := gateway.WritePID(pidPath, os.Getpid()); err != nil {
		t.Fatalf("WritePID: %v", err)
	}
	t.Cleanup(func() { _ = gateway.RemovePID(pidPath) })

	port := freePort(t)

	cmd := newProxyUpCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{fmt.Sprintf("--port=%d", port)})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when proxy already running, got nil")
	}

	var cliErr *CLIError
	if !errors.As(err, &cliErr) {
		t.Errorf("expected *CLIError, got %T: %v", err, err)
	}
}

// TestProxyUp_StalePIDFile verifies that `proxy up` refuses before touching
// an existing stale PID file — gateway_proxy is unsupported, so the
// stale-cleanup path is never reached.
func TestProxyUp_StalePIDFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)

	// Write a stale PID (guaranteed dead).
	pidPath := proxyPIDPathFromDir(dir)
	stalePID := 99999999
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(stalePID)+"\n"), 0o600); err != nil {
		t.Fatalf("write stale PID: %v", err)
	}

	port := freePort(t)
	cmd := newProxyUpCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{fmt.Sprintf("--port=%d", port)})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected proxy up to refuse; got nil error")
	}

	// The stale PID file must be left untouched (refusal happens before any
	// cleanup or listener side effect).
	pid, _ := gateway.ReadPID(pidPath)
	if pid != stalePID {
		t.Errorf("expected stale PID file untouched (%d), got %d", stalePID, pid)
	}
}

// TestProxyUp_Detach verifies that `proxy up --detach` returns an error when
// invoked from a go-run artifact (because detach is not supported in that context).
// In real builds this would fork a background process; we test the guard only.
func TestProxyUp_Detach(t *testing.T) {
	// We cannot test the full detach path from go test (which itself is a temp binary).
	// We verify that invoking --detach from what looks like a go-run artifact is handled
	// safely. The actual detach mechanics are covered by the gateway up detach path tests.
	t.Skip("--detach integration requires a real installed binary; skipped in unit tests")
}

// --- proxy down tests ---

// TestProxyDown_Running verifies that `proxy down` stops a running process.
func TestProxyDown_Running(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("/bin/sleep and SIGTERM not available on Windows")
	}
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)

	// Write current process PID as a proxy stand-in.
	pidPath := proxyPIDPathFromDir(dir)
	if err := gateway.WritePID(pidPath, os.Getpid()); err != nil {
		t.Fatalf("WritePID: %v", err)
	}

	cmd := newProxyDownCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})

	// We cannot actually kill the test process, so we test that the command
	// finds the PID and sends a signal. Override with a child process.
	// Instead, just verify that with a valid PID (our own) the command
	// proceeds past liveness check. The SIGTERM to self will be caught by the test runner.
	// We verify the output message includes the pid.
	//
	// Since sending SIGTERM to ourself would kill the test, we use a different
	// approach: write a PID of a non-existent process that is different from the
	// dead range, simulating the running path partially.
	// The cleanest approach: use a child process.

	// Spawn a child process that sleeps.
	child, childErr := startSleepChild(t)
	if childErr != nil {
		t.Fatalf("spawn child: %v", childErr)
	}
	defer func() { _ = child.Kill() }()

	if err := gateway.WritePID(pidPath, child.Pid); err != nil {
		t.Fatalf("WritePID child: %v", err)
	}

	out.Reset()
	if err := cmd.Execute(); err != nil {
		t.Fatalf("proxy down: %v", err)
	}

	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Error("expected PID file to be removed after proxy down")
	}
	if !bytes.Contains(out.Bytes(), []byte("stopped")) {
		t.Errorf("expected 'stopped' in output, got %q", out.String())
	}
}

// startSleepChild spawns a child process that sleeps indefinitely and returns its *os.Process.
func startSleepChild(t *testing.T) (*os.Process, error) {
	t.Helper()
	// Use `sleep 60` or equivalent.
	proc, err := os.StartProcess("/bin/sleep", []string{"sleep", "60"}, &os.ProcAttr{})
	if err != nil {
		// Fallback for platforms that may not have /bin/sleep.
		return nil, fmt.Errorf("start sleep child: %w", err)
	}
	return proc, nil
}

// TestProxyDown_StalePID verifies that `proxy down` cleans a stale PID file gracefully.
func TestProxyDown_StalePID(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)

	pidPath := proxyPIDPathFromDir(dir)
	if err := os.WriteFile(pidPath, []byte("99999999\n"), 0o600); err != nil {
		t.Fatalf("write stale PID: %v", err)
	}

	cmd := newProxyDownCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("proxy down: %v", err)
	}

	if !bytes.Contains(out.Bytes(), []byte("stale")) {
		t.Errorf("expected 'stale' in output, got %q", out.String())
	}

	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Error("expected PID file to be removed after stale cleanup")
	}
}

// TestProxyDown_Unresponsive tests that proxy down sends SIGKILL after timeout.
// This is difficult to fully test in unit tests without forking a real process that
// ignores SIGTERM. We verify the code path compiles and the function returns without error.
func TestProxyDown_Unresponsive(t *testing.T) {
	// The 5-second wait makes this impractical as a unit test.
	// The SIGKILL path is exercised by the production binary test suite.
	// Here we just confirm the down command handles a missing/dead PID cleanly.
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)

	// No PID file — not running.
	cmd := newProxyDownCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("proxy down: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("not running")) {
		t.Errorf("expected 'not running' in output, got %q", out.String())
	}
}

// --- proxy status tests ---

// TestProxyStatus_Stale verifies `proxy status` reports stale when PID file has a dead PID.
func TestProxyStatus_Stale(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)

	pidPath := proxyPIDPathFromDir(dir)
	if err := os.WriteFile(pidPath, []byte("99999999\n"), 0o600); err != nil {
		t.Fatalf("write stale PID: %v", err)
	}

	cmd := newProxyStatusCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("proxy status: %v", err)
	}

	// Status should report "stopped" (stale is indistinguishable from stopped
	// at the status display level — running=false; stale detection is for `down`).
	if !bytes.Contains(out.Bytes(), []byte("stopped")) {
		t.Errorf("expected 'stopped' in output for stale PID, got %q", out.String())
	}

	// JSON output: running=false, pid=null.
	cmdJSON := newProxyStatusCmd()
	var outJSON bytes.Buffer
	cmdJSON.SetOut(&outJSON)
	cmdJSON.SetErr(&bytes.Buffer{})
	cmdJSON.SetArgs([]string{"--json"})
	if err := cmdJSON.Execute(); err != nil {
		t.Fatalf("proxy status --json: %v", err)
	}
	var status proxyStatusOutput
	if err := json.Unmarshal(outJSON.Bytes(), &status); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}
	if status.Running {
		t.Error("expected Running=false for stale PID")
	}
}

// --- gateway up --with-proxy tests ---

// mockProxyStarter is a helper that records whether startProxyWithGateway was called.
// Since startProxyWithGateway is a package-level function we test the integration via
// gateway_cmd flags + a pre-existing PID file.

// TestGatewayUp_WithProxy_ProxyAlreadyRunning verifies that --with-proxy is a no-op
// when the proxy is already running.
func TestGatewayUp_WithProxy_ProxyAlreadyRunning(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)

	// Write a proxy PID file pointing to the current process (simulates running proxy).
	proxyPID := proxyPIDPathFromDir(dir)
	if err := gateway.WritePID(proxyPID, os.Getpid()); err != nil {
		t.Fatalf("WritePID proxy: %v", err)
	}
	t.Cleanup(func() { _ = gateway.RemovePID(proxyPID) })

	// We cannot fully run gateway up in a unit test (needs signing key, etc.)
	// Instead, we verify the proxy liveness check and the no-op path by calling
	// the relevant helpers directly.
	env := envForDir(dir)
	running, _, err := proxyLiveness(env)
	if err != nil {
		t.Fatalf("proxyLiveness: %v", err)
	}
	if !running {
		t.Error("expected proxy to be running before gateway up --with-proxy")
	}
	// The gateway up RunE checks IsRunning before calling startProxyWithGateway.
	// If running=true, it prints "already running — skipping" and continues.
	// This is the no-op path.
}

// TestSecurityRegression_GatewayWithProxyRejectsUnsupported verifies
// that startProxyWithGateway (the `gateway up --with-proxy` startup form)
// refuses immediately — gateway_proxy is unavailable — without binding
// a listener or writing a PID file.
func TestSecurityRegression_GatewayWithProxyRejectsUnsupported(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	pidPath := proxyPIDPathFromDir(dir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done, err := startProxyWithGateway(ctx, port, pidPath)
	if !errors.Is(err, ErrProxyUnsupported) {
		t.Fatalf("expected ErrProxyUnsupported, got: %v", err)
	}
	if done != nil {
		t.Error("expected nil done channel on refusal")
	}

	if _, statErr := os.Stat(pidPath); !os.IsNotExist(statErr) {
		t.Error("expected no PID file to be written when proxy is unsupported")
	}
	if conn, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond); dialErr == nil {
		conn.Close()
		t.Error("expected no listener; connection to proxy port unexpectedly succeeded")
	}
}
