//go:build containment && linux

package containment

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type relayReply struct {
	OK       bool   `json:"ok"`
	Kind     string `json:"kind"`
	Code     string `json:"code"`
	Error    string `json:"error"`
	ExitCode int    `json:"exit_code"`
	Session  *struct {
		Tier  string `json:"tier"`
		RunID string `json:"run_id"`
	} `json:"session"`
}

// relay runs keylatch-relay the way a harness runs an excluded command: on
// the host, with whatever arguments and stdin the agent chose.
func (e *sandboxEnv) relay(t *testing.T, stdin string, extraEnv []string, argv ...string) (reply relayReply, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(filepath.Join(e.bin, "keylatch-relay"), argv...)
	cmd.Env = cleanEnv(append([]string{"XDG_RUNTIME_DIR=" + e.runtimeDir}, extraEnv...)...)
	cmd.Stdin = strings.NewReader(stdin)
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
	if line, _, _ := strings.Cut(out.String(), "\n"); line != "" {
		if err := json.Unmarshal([]byte(line), &reply); err != nil {
			t.Fatalf("reply %q: %v", out.String(), err)
		}
	}
	return reply, errOut.String(), code
}

func requestLine(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

func (e *sandboxEnv) decisions(t *testing.T) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(e.auditFile)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var ev struct {
			Action string         `json:"action"`
			Extra  map[string]any `json:"extra"`
		}
		if json.Unmarshal([]byte(line), &ev) == nil && ev.Action == "run.decided" {
			out = append(out, ev.Extra)
		}
	}
	return out
}

func TestRelayWithHostileArgvStartsNothing(t *testing.T) {
	e := setup(t)
	canary := filepath.Join(e.root, "canary")
	touch := "touch " + canary

	runD5 := requestLine(t, map[string]any{"op": "run_session", "run": map[string]any{
		"connection": "openrouter", "tier": "D5", "command": []string{"sh", "-c", touch},
	}})
	runBare := requestLine(t, map[string]any{"op": "exec", "verb": "run", "args": []string{"openrouter", "--", "sh", "-c", touch}})

	argvs := [][]string{
		nil,
		{"--"},
		{"status"},
		{"run", "openrouter", "--", "sh", "-c", touch},
		{"; " + touch},
		{"$(" + touch + ")"},
		{"`" + touch + "`"},
		{"--socket", "/tmp/evil.sock"},
		{"-c", touch},
		{"-e", "sh", "--", "-c", touch},
	}
	var requests int
	for _, argv := range argvs {
		d5, errOut, code := e.relay(t, runD5, nil, argv...)
		requests++
		if code != 0 || d5.OK || d5.Code != "bad_request" || !strings.Contains(d5.Error, "D5") {
			t.Fatalf("argv %q: D5 run: exit %d reply %+v stderr %q", argv, code, d5, errOut)
		}
		bare, _, code := e.relay(t, runBare, nil, argv...)
		requests++
		if code != 0 || bare.OK || bare.Code != "bad_request" {
			t.Fatalf("argv %q: bare run: exit %d reply %+v", argv, code, bare)
		}
		if _, err := os.Stat(canary); err == nil {
			t.Fatalf("argv %q: a process outside the sandbox ran the canary command", argv)
		}
		if d5.Kind == "human" || bare.Kind == "human" {
			t.Fatalf("argv %q: a relayed request was classified as human", argv)
		}
	}

	// An allowed tier still starts nothing here: the daemon only issues a
	// session, and starting the child is the caller's own sandboxed client.
	ok, _, code := e.relay(t, requestLine(t, map[string]any{"op": "run_session", "run": map[string]any{
		"connection": "openrouter", "tier": "D2", "command": []string{"sh", "-c", touch},
	}}), nil, "run", "--", "sh", "-c", touch)
	requests++
	if code != 0 || !ok.OK || ok.Session == nil || ok.Session.Tier != "D2" {
		t.Fatalf("D2 session: exit %d reply %+v", code, ok)
	}
	if _, err := os.Stat(canary); err == nil {
		t.Fatal("the relay started the command of an allowed run")
	}

	time.Sleep(100 * time.Millisecond)
	decided := e.decisions(t)
	if len(decided) != requests {
		t.Fatalf("%d decisions for %d relayed requests: %+v", len(decided), requests, decided)
	}
	for _, d := range decided {
		if d["caller_kind"] == "human" {
			t.Errorf("decision classified a relayed request as human: %+v", d)
		}
	}
}

func TestRelayCannotObtainValues(t *testing.T) {
	e := setup(t)
	for _, verb := range []string{"get", "export", "backup", "mint"} {
		reply, _, code := e.relay(t, requestLine(t, map[string]any{"op": "exec", "verb": verb, "args": []string{"openrouter", "key"}}), nil)
		if code != 0 || reply.OK || reply.Code != "refused" || reply.Kind == "human" {
			t.Errorf("%s through the relay: exit %d reply %+v", verb, code, reply)
		}
	}
}

func TestRelayServesDaemonVerbs(t *testing.T) {
	e := setup(t)
	cmd := exec.Command(filepath.Join(e.bin, "keylatch-relay"))
	cmd.Env = cleanEnv("XDG_RUNTIME_DIR=" + e.runtimeDir)
	cmd.Stdin = strings.NewReader(requestLine(t, map[string]any{"op": "exec", "verb": "status"}))
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var stdout []byte
	var final relayReply
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		var frame struct {
			relayReply
			Stdout []byte `json:"stdout"`
		}
		if err := json.Unmarshal([]byte(line), &frame); err != nil {
			t.Fatalf("frame %q: %v", line, err)
		}
		stdout = append(stdout, frame.Stdout...)
		final = frame.relayReply
	}
	if !final.OK || !strings.Contains(string(stdout), "Vault") {
		t.Fatalf("status through the relay: final %+v stdout %q", final, stdout)
	}
}

func TestRelayRefusesAPlantedSocketOverride(t *testing.T) {
	e := setup(t)
	loose := filepath.Join(e.root, "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(loose, "keylatchd.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: planted, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
			accepted <- struct{}{}
		}
	}()

	_, errOut, code := e.relay(t, requestLine(t, map[string]any{"op": "exec", "verb": "status"}), []string{"KEYLATCH_SOCKET=" + planted})
	if code == 0 || !strings.Contains(errOut, "directory") {
		t.Fatalf("relay used a socket in a directory others can write: exit %d stderr %q", code, errOut)
	}
	select {
	case <-accepted:
		t.Fatal("the relay connected to the planted socket")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestRelayInsideTheSandboxReachesNothing(t *testing.T) {
	e := setup(t)
	probeArgs := []string{
		"--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
		"--unshare-pid", "--unshare-net", "--unshare-ipc", "--die-with-parent", "--clearenv",
		"--ro-bind", e.bin, e.bin, "--tmpfs", e.runtimeDir,
		"--setenv", "XDG_RUNTIME_DIR", e.runtimeDir,
		"--", filepath.Join(e.bin, "keylatch-relay"),
	}
	cmd := exec.Command("bwrap", probeArgs...)
	cmd.Stdin = strings.NewReader(requestLine(t, map[string]any{"op": "exec", "verb": "status"}))
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err == nil || out.Len() != 0 {
		t.Fatalf("the relay inside a sandbox without the socket answered %q (err %v)", out.String(), err)
	}
}

func TestRelayBinaryHasNoWayToStartAProcess(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "../../cmd/keylatch-relay")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	deps := strings.Fields(string(out))
	for _, forbidden := range []string{"os/exec", "plugin", "github.com/keylatch/keylatch/internal/control", "github.com/keylatch/keylatch/internal/store", "github.com/keylatch/keylatch/internal/vault"} {
		for _, d := range deps {
			if d == forbidden {
				t.Errorf("keylatch-relay links %s", forbidden)
			}
		}
	}
}
