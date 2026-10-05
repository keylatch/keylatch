package cli

import (
	"bufio"
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/testutil"
)

// The test binary doubles as a fake keylatch executable: commands that
// re-exec os.Executable() (setup wizard steps, gateway up --detach) land here
// when CB_KEYLATCH_FAKE is set, so no real binary or server is ever started.
const (
	cbFakeModeEnv = "CB_KEYLATCH_FAKE"
	cbFakeLogEnv  = "CB_KEYLATCH_FAKE_LOG"
)

func init() {
	mode := os.Getenv(cbFakeModeEnv)
	if mode == "" {
		return
	}
	os.Exit(cbFakeMain(mode, os.Args[1:]))
}

func cbFakeMain(mode string, args []string) int {
	if logPath := os.Getenv(cbFakeLogEnv); logPath != "" {
		if f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			_, _ = f.WriteString(strings.Join(args, " ") + "\n")
			_ = f.Close()
		}
	}
	joined := strings.Join(args, " ")
	isDetachedChild := strings.HasPrefix(joined, "gateway up") && !strings.Contains(joined, "--detach")
	switch mode {
	case "sleep":
		time.Sleep(time.Minute)
		return 0
	case "fail":
		return 1
	case "fail-gateway-init":
		if strings.HasPrefix(joined, "gateway init") {
			return 1
		}
	case "fail-gateway-up":
		if strings.HasPrefix(joined, "gateway up") {
			return 1
		}
	case "no-pid":
		return 0
	}
	if isDetachedChild {
		pidPath := paths.GatewayPID(os.Getenv)
		_ = os.MkdirAll(filepath.Dir(pidPath), 0o700)
		_ = os.WriteFile(pidPath, []byte("4242\n"), 0o600)
	}
	return 0
}

// cbIsolate points every keylatch path at a fresh temp tree, blanks LLM
// session signals and returns the config dir.
func cbIsolate(t *testing.T) string {
	t.Helper()
	testutil.ClearLLMSessionEnv(t)
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "keylatch")
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("KEYLATCH_CONFIG_DIR", cfgDir)
	for _, k := range []string{
		"KEYLATCH_ACTORS_PATH", "KEYLATCH_APPROVALS_DIR", "KEYLATCH_AUDIT_PATH",
		"KEYLATCH_AUDIT_SALT_PATH", "KEYLATCH_CONFIG", "KEYLATCH_DAEMON_STATE_PATH",
		"KEYLATCH_GATEWAY_CONFIG", "KEYLATCH_GATEWAY_DIR", "KEYLATCH_GATEWAY_LOG",
		"KEYLATCH_GATEWAY_PID", "KEYLATCH_GATEWAY_RULES", "KEYLATCH_GATEWAY_SIGNING_KEY",
		"KEYLATCH_GATEWAY_TOKENS", "KEYLATCH_GRANT_ACCESSOR_KEY_PATH", "KEYLATCH_GRANTS_DIR",
		"KEYLATCH_GRANTS_PATH", "KEYLATCH_KEYRING_DIR", "KEYLATCH_KEYRING_IDENTITY_PATH",
		"KEYLATCH_KEYRING_PATH", "KEYLATCH_POLICY_PATH", "KEYLATCH_PROJECTS_PATH",
		"KEYLATCH_RECEIPTS_PATH", "KEYLATCH_SESSIONS_PATH", "KEYLATCH_VAULT_PATH",
		"KEYLATCH_AGE_IDENTITY", "KEYLATCH_MODE", "KEYLATCH_EXPERIMENTAL",
		"KEYLATCH_GATEWAY_LISTEN", "KEYLATCH_UI_LISTEN", "KEYLATCH_GATEWAY_ADDR",
		"KEYLATCH_PROXY_ADDR", cbFakeModeEnv, cbFakeLogEnv,
	} {
		t.Setenv(k, "")
	}
	return cfgDir
}

// cbRun executes the real root command tree with args and captured output.
func cbRun(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	return cbRunIn(t, "", args...)
}

func cbRunIn(t *testing.T, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errBuf bytes.Buffer
	root := NewRootCommand()
	root.SetOut(&out)
	root.SetErr(&errBuf)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(args)
	err = root.Execute()
	return out.String(), errBuf.String(), err
}

// cbRunToFiles is cbRun with *os.File sinks: children started without Wait
// then inherit the descriptors directly instead of racing a copy goroutine
// against the test reading a buffer.
func cbRunToFiles(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	dir := t.TempDir()
	outF, ferr := os.Create(filepath.Join(dir, "stdout"))
	if ferr != nil {
		t.Fatal(ferr)
	}
	errF, ferr := os.Create(filepath.Join(dir, "stderr"))
	if ferr != nil {
		t.Fatal(ferr)
	}
	t.Cleanup(func() { _ = outF.Close(); _ = errF.Close() })
	root := NewRootCommand()
	root.SetOut(outF)
	root.SetErr(errF)
	root.SetArgs(args)
	err = root.Execute()
	o, _ := os.ReadFile(outF.Name())
	e, _ := os.ReadFile(errF.Name())
	return string(o), string(e), err
}

// cbScriptStdin feeds the wizard's shared line reader from input.
func cbScriptStdin(t *testing.T, input string) {
	t.Helper()
	oldFn := stdinScannerFn
	t.Cleanup(func() {
		stdinScannerFn = oldFn
		scannerOnce = &sync.Once{}
		sharedScanner = nil
	})
	scannerOnce = &sync.Once{}
	sharedScanner = nil
	stdinScannerFn = func() *bufio.Scanner {
		return bufio.NewScanner(strings.NewReader(input))
	}
}

// cbFakeSelf makes re-execs of the test binary behave as a fake keylatch in
// the given mode and returns the path of the file recording their argv.
func cbFakeSelf(t *testing.T, mode string) string {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "argv.log")
	t.Setenv(cbFakeModeEnv, mode)
	t.Setenv(cbFakeLogEnv, logPath)
	return logPath
}

func cbReadLog(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// cbBusyPort holds a loopback listener open for the test so any server asked
// to bind that port fails immediately instead of serving forever.
func cbBusyPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

func cbMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

func cbWaitFor(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}
