//go:build containment && linux

// Package containment runs the thin client inside a bubblewrap sandbox that
// hides Keylatch state and exposes only the daemon's control socket.
package containment

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/harness"
)

type sandboxEnv struct {
	root, bin, fakeBin, runtimeDir, state, gatewayAddr, auditFile string
	auth                                               chan string
}

func requireBwrap(t *testing.T) {
	t.Helper()
	path, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("bwrap is not installed")
	}
	if out, err := exec.Command(path, "--ro-bind", "/", "/", "--unshare-pid", "--unshare-net", "true").CombinedOutput(); err != nil {
		t.Skipf("bwrap cannot create namespaces here: %v: %s", err, out)
	}
}

func build(t *testing.T, out string, pkgs ...string) {
	t.Helper()
	cmd := exec.Command("go", append([]string{"build", "-o", out}, pkgs...)...)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %v: %v\n%s", pkgs, err, b)
	}
}

// cleanEnv drops every agent signal and Keylatch setting from the host
// environment so the daemon behaves as one started from a plain terminal.
func cleanEnv(extra ...string) []string {
	signals := map[string]bool{}
	for _, s := range harness.Signals() {
		signals[s.Name] = true
	}
	var out []string
	for _, e := range os.Environ() {
		name, _, _ := strings.Cut(e, "=")
		if signals[name] || strings.HasPrefix(name, "KEYLATCH_") || name == "XDG_RUNTIME_DIR" || name == "HOME" {
			continue
		}
		out = append(out, e)
	}
	return append(out, extra...)
}

func setup(t *testing.T) *sandboxEnv {
	t.Helper()
	requireBwrap(t)
	root, err := os.MkdirTemp("/tmp", "klc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	e := &sandboxEnv{
		root:       root,
		bin:        filepath.Join(root, "bin"),
		fakeBin:    filepath.Join(root, "fakebin"),
		runtimeDir: filepath.Join(root, "run"),
		state:      filepath.Join(root, "state"),
		auth:       make(chan string, 8),
	}
	for _, d := range []string{e.bin, e.fakeBin, e.runtimeDir, filepath.Join(e.state, "gateway"), filepath.Join(root, "home")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(e.state, "gateway", "signing.key"), bytes.Repeat([]byte{9}, 32), 0o600); err != nil {
		t.Fatal(err)
	}

	build(t, e.bin+"/", "../../cmd/keylatch", "../../cmd/keylatch-relay")
	build(t, filepath.Join(e.bin, "probe"), "./testdata/probe")
	build(t, filepath.Join(e.bin, "controld"), "./testdata/controld")

	fake := "#!/bin/sh\nexec " + filepath.Join(e.bin, "probe") + " fake-client \"$XDG_RUNTIME_DIR/keylatch/keylatchd.sock\" \"$@\"\n"
	if err := os.WriteFile(filepath.Join(e.fakeBin, "keylatch"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}

	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.auth <- r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "gateway-reached")
	}))
	t.Cleanup(gw.Close)
	e.gatewayAddr = gw.Listener.Addr().String()

	e.auditFile = filepath.Join(root, "audit.jsonl")
	daemon := exec.Command(filepath.Join(e.bin, "controld"), "--keylatch-bin", filepath.Join(e.bin, "keylatch"), "--audit", e.auditFile)
	daemon.Env = cleanEnv(
		"HOME="+filepath.Join(root, "home"),
		"XDG_RUNTIME_DIR="+e.runtimeDir,
		"KEYLATCH_CONFIG_DIR="+e.state,
		"KEYLATCH_GATEWAY_ADDR="+e.gatewayAddr,
	)
	var daemonLog bytes.Buffer
	daemon.Stdout, daemon.Stderr = &daemonLog, &daemonLog
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = daemon.Process.Kill()
		_ = daemon.Wait()
	})

	socket := filepath.Join(e.runtimeDir, "keylatch", "keylatchd.sock")
	deadline := time.Now().Add(15 * time.Second)
	for {
		if c, err := net.Dial("unix", socket); err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon did not start: %s", daemonLog.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	return e
}

// sandboxed runs argv in a sandbox with its own PID, network and IPC
// namespaces, an empty /tmp, and only the binaries and the control socket
// directory mounted back in.
func (e *sandboxEnv) sandboxed(t *testing.T, pathDirs []string, argv ...string) (stdout, stderr string, code int) {
	t.Helper()
	args := []string{
		"--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
		"--unshare-pid", "--unshare-net", "--unshare-ipc", "--die-with-parent", "--clearenv",
		"--ro-bind", e.bin, e.bin, "--ro-bind", e.fakeBin, e.fakeBin, "--bind", e.runtimeDir, e.runtimeDir,
		"--setenv", "PATH", strings.Join(append(pathDirs, "/usr/bin", "/bin"), ":"),
		"--setenv", "HOME", "/tmp/home",
		"--setenv", "XDG_RUNTIME_DIR", e.runtimeDir,
		"--",
	}
	cmd := exec.Command("bwrap", append(args, argv...)...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	default:
		t.Fatal(err)
	}
	return out.String(), errOut.String(), code
}

func TestSandboxHidesStateAndHostNetwork(t *testing.T) {
	e := setup(t)
	probe := filepath.Join(e.bin, "probe")

	out, _, code := e.sandboxed(t, []string{e.bin}, probe, "hidden", e.state)
	if code != 0 || strings.TrimSpace(out) != "hidden" {
		t.Fatalf("Keylatch state is visible in the sandbox: %q (exit %d)", out, code)
	}
	out, _, code = e.sandboxed(t, []string{e.bin}, probe, "dial", e.gatewayAddr)
	if code != 0 || strings.TrimSpace(out) != "unreachable" {
		t.Fatalf("host gateway is reachable from the sandbox: %q (exit %d)", out, code)
	}
}

func TestStatusByBareNameInsideSandbox(t *testing.T) {
	e := setup(t)
	out, errOut, code := e.sandboxed(t, []string{e.bin}, "keylatch", "status")
	if code != 0 || !strings.Contains(out, "Vault") {
		t.Fatalf("status through the daemon: exit %d stdout=%q stderr=%q", code, out, errOut)
	}
	if !strings.Contains(out, "LLM session   active") {
		t.Errorf("the daemon must run a sandboxed caller's verbs as an agent session: %q", out)
	}
}

func TestRunD2ByBareNameInsideSandbox(t *testing.T) {
	e := setup(t)
	probe := filepath.Join(e.bin, "probe")

	out, errOut, code := e.sandboxed(t, []string{e.bin},
		"keylatch", "run", "--tier", "D2", "openrouter", "--", probe, "gateway")
	if code != 0 {
		t.Fatalf("run --tier D2: exit %d stdout=%q stderr=%q", code, out, errOut)
	}
	if strings.TrimSpace(out) != "gateway-reached|" {
		t.Fatalf("child output %q: want the gateway body and no provider key", out)
	}
	select {
	case auth := <-e.auth:
		if !strings.HasPrefix(auth, "Bearer ") || strings.Count(auth, ".") != 2 {
			t.Errorf("gateway received %q, want a session token", auth)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the gateway never saw the child's request")
	}

	_, errOut, code = e.sandboxed(t, []string{e.bin}, "keylatch", "run", "--tier", "D6", "openrouter", "--", "true")
	if code != 2 || !strings.Contains(errOut, "D6") {
		t.Errorf("D6: exit %d stderr=%q, want refusal", code, errOut)
	}
}

func TestValueVerbsRefusedInsideSandbox(t *testing.T) {
	e := setup(t)
	for _, verb := range []string{"get", "export", "backup", "mint"} {
		out, errOut, code := e.sandboxed(t, []string{e.bin}, "keylatch", verb, "openrouter", "key")
		if code != 2 || out != "" || !strings.Contains(errOut, "not available to") {
			t.Errorf("%s: exit %d stdout=%q stderr=%q, want a refusal with no output", verb, code, out, errOut)
		}
	}
}

func TestPlantedKeylatchObtainsNoValue(t *testing.T) {
	e := setup(t)
	out, _, code := e.sandboxed(t, []string{e.fakeBin, e.bin}, "keylatch", "get", "openrouter", "key")
	if code != 0 {
		t.Fatalf("fake client exit %d: %q", code, out)
	}
	var resp struct {
		OK       bool   `json:"ok"`
		Kind     string `json:"kind"`
		ExitCode int    `json:"exit_code"`
		Stdout   string `json:"stdout"`
		Code     string `json:"code"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("daemon answer %q: %v", out, err)
	}
	if resp.OK || resp.Stdout != "" || resp.Code != "refused" || (resp.Kind != "host" && resp.Kind != "agent") {
		t.Errorf("a planted client got %+v, want a refusal as a host or agent caller", resp)
	}
}
