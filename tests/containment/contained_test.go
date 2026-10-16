//go:build containment && linux

package containment

// Escape cases for tier D5: a hostile command that holds the real value inside
// the Keylatch sandbox. The daemon is the real control server with the real
// launcher; only the provider and the sink are local servers. A host without
// unprivileged user namespaces, Landlock or Unix sockets skips these tests and
// says which capability is missing; nothing here passes by default.

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/contained"
)

type containedEnv struct {
	root, bin, runtimeDir, state, home, project, auditFile, sinkAddr, caFile string
	daemonPID                                                                int
	provider                                                                 *httptest.Server

	mu       sync.Mutex
	hits     []hit
	sinkHits int
}

func requireContained(t *testing.T) {
	t.Helper()
	if missing := contained.Probe().Missing(); len(missing) > 0 {
		t.Skipf("the contained tier is unavailable here: %s", strings.Join(missing, "; "))
	}
	dir := t.TempDir()
	l, err := net.Listen("unix", filepath.Join(dir, "probe.sock"))
	if err != nil {
		t.Skipf("this host does not let tests create Unix sockets: %v", err)
	}
	_ = l.Close()
}

func setupContained(t *testing.T, approve string) *containedEnv {
	t.Helper()
	requireContained(t)
	root, err := os.MkdirTemp("/tmp", "klx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	e := &containedEnv{
		root: root, bin: filepath.Join(root, "bin"), runtimeDir: filepath.Join(root, "run"), state: filepath.Join(root, "state"),
		home: filepath.Join(root, "home"), project: filepath.Join(root, "project"), auditFile: filepath.Join(root, "audit.jsonl"),
	}
	for _, d := range []string{e.bin, e.runtimeDir, e.state, e.home, e.project, filepath.Join(root, "runs")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	build(t, e.bin+"/", "../../cmd/keylatch")
	build(t, filepath.Join(e.bin, "containedd"), "./testdata/containedd")
	build(t, filepath.Join(e.project, "probe"), "./testdata/probe")

	cert, certPEM := fakeProviderCert(t)
	e.caFile = filepath.Join(e.project, "ca.pem")
	if err := os.WriteFile(e.caFile, []byte(certPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	e.provider = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		e.mu.Lock()
		e.hits = append(e.hits, hit{r.Host, r.Method, r.URL.Path, r.URL.RawQuery, r.Proto, r.Header.Get("Authorization"), r.Header.Get("x-api-key"), r.Header.Clone(), string(b)})
		e.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	e.provider.EnableHTTP2 = true
	e.provider.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	e.provider.StartTLS()
	t.Cleanup(e.provider.Close)

	sink, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	e.sinkAddr = sink.Addr().String()
	go func() {
		for {
			c, err := sink.Accept()
			if err != nil {
				return
			}
			e.mu.Lock()
			e.sinkHits++
			e.mu.Unlock()
			_ = c.Close()
		}
	}()

	daemon := exec.Command(filepath.Join(e.bin, "containedd"),
		"--upstream", e.provider.Listener.Addr().String(), "--audit", e.auditFile, "--secret", canary,
		"--keylatch-bin", filepath.Join(e.bin, "keylatch"), "--runs", filepath.Join(root, "runs"), "--approve", approve)
	daemon.Env = cleanEnv("HOME="+e.home, "XDG_RUNTIME_DIR="+e.runtimeDir, "KEYLATCH_CONFIG_DIR="+e.state)
	var daemonLog bytes.Buffer
	daemon.Stdout, daemon.Stderr = &daemonLog, &daemonLog
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	e.daemonPID = daemon.Process.Pid
	t.Cleanup(func() {
		_ = daemon.Process.Kill()
		_ = daemon.Wait()
	})
	socket := filepath.Join(e.runtimeDir, "keylatch", "keylatchd.sock")
	deadline := time.Now().Add(20 * time.Second)
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

// run executes argv in the sandbox through `keylatch run --tier D5` from the
// project directory, as a plain terminal user unless extraEnv says otherwise.
func (e *containedEnv) run(t *testing.T, extraEnv []string, flags []string, argv ...string) (string, string, int) {
	t.Helper()
	args := append([]string{"run", "--tier", "D5"}, flags...)
	args = append(args, "stripe", "--")
	cmd := exec.Command(filepath.Join(e.bin, "keylatch"), append(args, argv...)...)
	cmd.Dir = e.project
	cmd.Env = cleanEnv(append([]string{"HOME=" + e.home, "XDG_RUNTIME_DIR=" + e.runtimeDir, "KEYLATCH_CONFIG_DIR=" + e.state}, extraEnv...)...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	code := 0
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

func (e *containedEnv) audit(t *testing.T) []auditLine {
	t.Helper()
	raw, err := os.ReadFile(e.auditFile)
	if err != nil {
		t.Fatal(err)
	}
	var out []auditLine
	for _, line := range bytes.Split(raw, []byte("\n")) {
		var l auditLine
		if len(line) > 0 && json.Unmarshal(line, &l) == nil {
			out = append(out, l)
		}
	}
	return out
}

func (e *containedEnv) count(t *testing.T, action string) int {
	n := 0
	for _, l := range e.audit(t) {
		if l.Action == action {
			n++
		}
	}
	return n
}

func (e *containedEnv) providerHits() []hit {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]hit(nil), e.hits...)
}

func (e *containedEnv) noCanaryOnDisk(t *testing.T) {
	t.Helper()
	if raw, _ := os.ReadFile(e.auditFile); bytes.Contains(raw, []byte(canary)) {
		t.Error("the audit log holds the credential")
	}
}

func (e *containedEnv) probe() string { return "./probe" }

// Case 1: environment and /proc dumps.
func TestContainedEnvironmentHoldsTheValueButNothingLeavesWithIt(t *testing.T) {
	e := setupContained(t, "deny")
	script := `test "$STRIPE_SECRET_KEY" = '` + canary + `' && echo has-value; env; cat /proc/self/environ | tr '\0' '\n'; echo "$STRIPE_SECRET_KEY" >&2`
	out, errOut, code := e.run(t, nil, nil, "sh", "-c", script)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "has-value") {
		t.Error("the sandboxed command did not receive the value")
	}
	if strings.Contains(out, canary) || strings.Contains(errOut, canary) {
		t.Fatal("the value came back in the relayed output")
	}
	e.noCanaryOnDisk(t)
}

// Case 2: every route to a host the policy does not name.
func TestContainedExfiltrationRoutesAreClosed(t *testing.T) {
	e := setupContained(t, "deny")
	out, errOut, code := e.run(t, nil, nil, e.probe(), "exfil", e.sinkAddr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 12 {
		t.Fatalf("probe output too short: %q", out)
	}
	for _, l := range lines {
		if !strings.HasSuffix(l, "=blocked") {
			t.Errorf("%s", l)
		}
	}
	time.Sleep(200 * time.Millisecond)
	e.mu.Lock()
	hits := e.sinkHits
	e.mu.Unlock()
	if hits != 0 {
		t.Errorf("the sink received %d connections", hits)
	}
	if n := len(e.providerHits()); n != 0 {
		t.Errorf("a provider saw %d requests from the exfiltration attempts", n)
	}
	if e.count(t, "egress.denied") == 0 {
		t.Error("no egress.denied event")
	}
	e.noCanaryOnDisk(t)
}

// Case 3: the egress proxy lets the bound hosts through and nothing else, and
// the value reaches only a bound host.
func TestContainedEgressReachesOnlyTheBoundHosts(t *testing.T) {
	e := setupContained(t, "deny")
	flags := []string{"--extra", "SSL_CERT_FILE"}
	env := []string{"SSL_CERT_FILE=" + e.caFile}
	bearer := "Authorization=Bearer $STRIPE_SECRET_KEY"

	out, errOut, code := e.run(t, env, flags, "sh", "-c", shellJoin([]string{e.probe(), "request", "GET", "https://api.stripe.com/v1/balance", "-H", bearer}))
	if code != 0 || !strings.Contains(out, "status=200") {
		t.Fatalf("a bound host was not reachable: exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	if strings.Contains(out, canary) {
		t.Fatal("the value came back in the relayed output")
	}
	hits := e.providerHits()
	if len(hits) != 1 || hits[0].Host != "api.stripe.com" || hits[0].Auth != "Bearer "+canary {
		t.Fatalf("the bound host should receive the value in its slot, got %+v", hits)
	}

	for name, target := range map[string]string{
		"another host":   "https://api.github.com/user",
		"an ip literal":  "https://203.0.113.9/x",
		"loopback name":  "https://localhost:" + strconv.Itoa(e.provider.Listener.Addr().(*net.TCPAddr).Port) + "/x",
		"a wrong port":   "https://api.stripe.com:8443/x",
		"plain http out": "http://api.stripe.com/x",
	} {
		before := len(e.providerHits())
		out, _, _ := e.run(t, env, flags, "sh", "-c", shellJoin([]string{e.probe(), "request", "GET", target, "-H", bearer}))
		if !strings.Contains(out, "error:") && !strings.Contains(out, "status=403") && !strings.Contains(out, "status=400") {
			t.Errorf("%s: %q", name, out)
		}
		if n := len(e.providerHits()); n != before {
			t.Errorf("%s reached the provider", name)
		}
	}
	if e.count(t, "egress.denied") == 0 {
		t.Error("no egress.denied event")
	}
	e.noCanaryOnDisk(t)
}

// Case 4: state and credential stores are absent, not masked.
func TestContainedStateAndCredentialStoresAreAbsent(t *testing.T) {
	e := setupContained(t, "deny")
	planted := []string{
		filepath.Join(e.state, "keyring", "identity"),
		filepath.Join(e.home, ".ssh", "id_ed25519"),
		filepath.Join(e.home, ".aws", "credentials"),
		filepath.Join(e.home, ".config", "google-chrome", "Default", "Login Data"),
		filepath.Join(e.runtimeDir, "bus"),
		filepath.Join(e.runtimeDir, "keylatch", "keylatchd.sock"),
	}
	for _, p := range planted {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(p); err != nil {
			if err := os.WriteFile(p, []byte("planted"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, p := range planted {
		out, errOut, code := e.run(t, nil, nil, e.probe(), "hidden", p)
		if code != 0 || strings.TrimSpace(out) != "hidden" {
			t.Errorf("%s is visible inside the sandbox: %q %q (exit %d)", p, out, errOut, code)
		}
	}
	// A project that holds credentials is refused outright.
	cmd := exec.Command(filepath.Join(e.bin, "keylatch"), "run", "--tier", "D5", "stripe", "--", "true")
	cmd.Dir = filepath.Join(e.home, ".ssh")
	cmd.Env = cleanEnv("HOME="+e.home, "XDG_RUNTIME_DIR="+e.runtimeDir, "KEYLATCH_CONFIG_DIR="+e.state)
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "not available to contained runs") {
		t.Errorf("a run from ~/.ssh was not refused: %v %s", err, out)
	}
}

// Case 5: the daemon cannot be traced, read or signalled from inside.
func TestContainedChildCannotReachTheDaemon(t *testing.T) {
	e := setupContained(t, "deny")
	out, errOut, code := e.run(t, nil, nil, e.probe(), "ptrace", strconv.Itoa(e.daemonPID))
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if !strings.HasSuffix(l, "=blocked") {
			t.Errorf("%s", l)
		}
	}
}

// Case 6: nothing outlives the run, however it detaches.
func TestContainedForkedChildrenDieWithTheRun(t *testing.T) {
	e := setupContained(t, "deny")
	const marker = "600.424242"
	out, errOut, code := e.run(t, nil, nil, "sh", "-c", "(setsid sleep "+marker+" &); (sleep "+marker+" &); sleep "+marker+" & echo started")
	if code != 0 || !strings.Contains(out, "started") {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		left := processesWith(marker)
		if len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("processes outlived the run: %v", left)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func processesWith(marker string) []string {
	entries, _ := os.ReadDir("/proc")
	var found []string
	for _, ent := range entries {
		if _, err := strconv.Atoi(ent.Name()); err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", ent.Name(), "cmdline"))
		if err == nil && bytes.Contains(raw, []byte(marker)) {
			found = append(found, ent.Name())
		}
	}
	return found
}

// Case 7: nested sandboxes, traversal, links and /proc tricks.
func TestContainedNestedSandboxEscapesFail(t *testing.T) {
	e := setupContained(t, "deny")
	out, errOut, code := e.run(t, nil, nil, e.probe(), "nested")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if !strings.HasSuffix(l, "=blocked") {
			t.Errorf("%s", l)
		}
	}
	protected := filepath.Join(e.state, "keyring", "identity")
	if err := os.MkdirAll(filepath.Dir(protected), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(protected, []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, code = e.run(t, nil, nil, e.probe(), "traverse", e.project, protected)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if !strings.HasSuffix(l, "=blocked") {
			t.Errorf("%s", l)
		}
	}
}

// Case 8: what the relay catches and what no scanner can.
func TestContainedEncodedLeaksAreCaughtAndXORIsNot(t *testing.T) {
	e := setupContained(t, "deny")
	out, errOut, code := e.run(t, nil, nil, e.probe(), "encode", "STRIPE_SECRET_KEY")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for form, encoded := range map[string]string{
		"plain":     canary,
		"base64":    base64.StdEncoding.EncodeToString([]byte(canary)),
		"base64url": base64.RawURLEncoding.EncodeToString([]byte(canary)),
		"hex":       hex.EncodeToString([]byte(canary)),
		"url":       url.QueryEscape(canary),
	} {
		if strings.Contains(out, encoded) {
			t.Errorf("the %s form came back unredacted", form)
		}
	}
	// A constant XOR and a split across lines are documented as not caught:
	// they are why D5 asks for approval by default.
	xor := make([]byte, len(canary))
	for i := range canary {
		xor[i] = canary[i] ^ 0x2a
	}
	if !strings.Contains(out, hex.EncodeToString(xor)) {
		t.Error("the XOR form was expected to pass the relay; if it is caught now, update the documentation")
	}

	_, errOut, code = e.run(t, nil, nil, e.probe(), "encode", "STRIPE_SECRET_KEY", "dump.b64")
	if code != 3 {
		t.Errorf("a secret written to a file under the project should exit 3, got %d: %s", code, errOut)
	}
	if e.count(t, "contained.leak_suspected") == 0 {
		t.Error("no contained.leak_suspected event")
	}
	e.noCanaryOnDisk(t)
}

// Case 10: an agent needs an approval, and a refusal starts nothing.
func TestContainedNeedsAnApprovalFromAgents(t *testing.T) {
	e := setupContained(t, "deny")
	out, errOut, code := e.run(t, []string{"CLAUDECODE=1"}, nil, "sh", "-c", "echo ran")
	if code != 4 || strings.Contains(out, "ran") {
		t.Fatalf("an agent without approval must be refused with exit 4, got %d: %s %s", code, out, errOut)
	}
	if !strings.Contains(errOut, "approval refused") {
		t.Errorf("the refusal does not say why: %q", errOut)
	}

	granted := setupContained(t, "allow")
	out, errOut, code = granted.run(t, []string{"CLAUDECODE=1"}, nil, "sh", "-c", "echo ran")
	if code != 0 || !strings.Contains(out, "ran") {
		t.Fatalf("an approved agent run failed: %d %s %s", code, out, errOut)
	}
	if granted.count(t, "run.decided") == 0 {
		t.Error("no run.decided event")
	}
}
