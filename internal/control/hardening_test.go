//go:build !windows

package control

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/audit/fields"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"golang.org/x/crypto/ssh"
)

const streamScript = `#!/bin/sh
case "$1" in
doctor)
  head -c 25165824 /dev/zero | tr '\0' 'x'
  echo "tail" >&2
  ;;
call)
  while read -r line; do echo "got:$line"; done
  ;;
list)
  echo one
  while [ ! -e "$GATE" ]; do sleep 0.02; done
  echo two
  ;;
describe)
  exit 7
  ;;
*)
  echo "args:$*"
  ;;
esac
`

type failingAudit struct{}

func (failingAudit) Emit(context.Context, audit.Event) error { return errors.New("disk full") }

func (r *recordingAudit) byAction(action audit.Action) []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []audit.Event
	for _, e := range r.events {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func (r *recordingAudit) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

func (r *recordingAudit) dump() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, _ := json.Marshal(r.events)
	return string(b)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestEveryDecisionProducesOneAuditEvent(t *testing.T) {
	addr, _ := fakeGateway(t)
	rec := &recordingAudit{}
	_, env := startDaemonWith(t, addr, streamScript, func(c *Config) { c.Audit = rec })
	agentEnv := map[string]string{"KEYLATCH_AGENT_SESSION": "1"}
	for k, v := range env {
		agentEnv[k] = v
	}
	human, _ := NewClient(lookupOf(env))
	agentClient, _ := NewClient(lookupOf(agentEnv))

	type step struct {
		name    string
		do      func() error
		outcome audit.Outcome
		kind    string
		exited  bool
	}
	var token string
	steps := []step{
		{"served verb", func() error { _, err := human.Exec(nil, "status", nil); return err }, audit.OutcomeOK, "human", true},
		{"agent served verb", func() error { _, err := agentClient.Exec(nil, "status", nil); return err }, audit.OutcomeOK, "agent", true},
		{"value verb for an agent", func() error { _, err := agentClient.Exec(nil, "get", []string{"svc", "key"}); return err }, audit.OutcomeDenied, "agent", false},
		{"value verb for a human runs locally", func() error { _, err := human.Exec(nil, "get", []string{"svc", "key"}); return err }, audit.OutcomeOK, "human", false},
		{"unserved verb", func() error { _, err := human.Exec(nil, "bogus", nil); return err }, audit.OutcomeDenied, "human", false},
		{"bare run", func() error { _, err := human.Exec(nil, "run", []string{"x"}); return err }, audit.OutcomeDenied, "human", false},
		{"nul byte", func() error { _, err := human.Exec(nil, "status", []string{"a\x00b"}); return err }, audit.OutcomeDenied, "human", false},
		{"uncontained tier", func() error {
			_, err := agentClient.RunSession(RunRequest{Connection: "openrouter", Command: []string{"sh", "-c", "x"}, Tier: TierRaw})
			return err
		}, audit.OutcomeDenied, "agent", false},
		{"unknown connection", func() error {
			_, err := human.RunSession(RunRequest{Connection: "nope", Command: []string{"true"}})
			return err
		}, audit.OutcomeDenied, "human", false},
		{"gateway session", func() error {
			resp, err := agentClient.RunSession(RunRequest{Connection: "openrouter", Command: []string{"sh", "-c", "echo hi"}, CWD: "/work"})
			if err != nil || !resp.OK {
				return fmt.Errorf("session: %+v %v", resp, err)
			}
			token = resp.Session.Env.Set[0].Value
			agentClient.SetRun(resp.Session.RunID)
			return agentClient.ReportExit(3)
		}, audit.OutcomeOK, "agent", true},
		{"unknown operation", func() error {
			conn, err := human.dial()
			if err != nil {
				return err
			}
			defer func() { _ = conn.Close() }()
			if err := writeFrame(conn, Request{Op: "frobnicate"}); err != nil {
				return err
			}
			var resp Response
			return readFrame(bufio.NewReader(conn), &resp, maxFrame)
		}, audit.OutcomeDenied, "human", false},
	}
	for _, st := range steps {
		before := rec.count()
		if err := st.do(); err != nil {
			t.Fatalf("%s: %v", st.name, err)
		}
		waitFor(t, st.name, func() bool { return len(rec.byAction(audit.ActionRunDecided)) > 0 })
		want := 1
		if st.exited {
			want = 2
		}
		waitFor(t, st.name+" events", func() bool { return rec.count()-before >= want })
		time.Sleep(20 * time.Millisecond)
		if got := rec.count() - before; got != want {
			t.Fatalf("%s: %d events, want %d: %s", st.name, got, want, rec.dump())
		}
		rec.mu.Lock()
		evs := rec.events[before:]
		rec.mu.Unlock()
		if evs[0].Action != audit.ActionRunDecided || evs[0].Outcome != st.outcome {
			t.Errorf("%s: first event %s/%s, want run.decided/%s", st.name, evs[0].Action, evs[0].Outcome, st.outcome)
		}
		if evs[0].Extra["caller_kind"] != st.kind {
			t.Errorf("%s: caller_kind %v, want %s", st.name, evs[0].Extra["caller_kind"], st.kind)
		}
		if st.exited && evs[1].Action != audit.ActionRunExited {
			t.Errorf("%s: second event %s, want run.exited", st.name, evs[1].Action)
		}
	}

	dump := rec.dump()
	if token == "" || strings.Contains(dump, token) {
		t.Errorf("a session token reached the audit log (token %q)", token)
	}
	for _, leak := range []string{"echo hi", "/work", "sk-", "Bearer"} {
		if strings.Contains(dump, leak) {
			t.Errorf("audit holds %q: %s", leak, dump)
		}
	}
	sessions := rec.byAction(audit.ActionRunDecided)
	var session audit.Event
	for _, e := range sessions {
		if e.Extra["op"] == string(OpRunSession) && e.Outcome == audit.OutcomeOK {
			session = e
		}
	}
	for _, key := range []string{"tier", "child_location", "argv_sha256", "cwd_sha256", "connection", "run_id"} {
		if session.Extra[key] == nil {
			t.Errorf("session decision lacks %s: %+v", key, session.Extra)
		}
	}
	if session.Extra["child_location"] != childInCaller || session.Extra["tier"] != string(TierGateway) {
		t.Errorf("session decision = %+v", session.Extra)
	}
	exits := rec.byAction(audit.ActionRunExited)
	if last := exits[len(exits)-1]; last.Extra["exit"] != 3 || last.Outcome != audit.OutcomeError {
		t.Errorf("reported exit = %+v", last)
	}

	salt := bytes.Repeat([]byte{1}, 32)
	for _, e := range append(sessions, exits...) {
		got := fields.Redact(salt, string(e.Action), e.Extra)
		for k, v := range e.Extra {
			if fmt.Sprint(got[k]) != fmt.Sprint(v) {
				t.Errorf("%s field %q is not in the allowlist", e.Action, k)
			}
		}
	}
}

func TestDecisionRefusedWhenAuditCannotRecord(t *testing.T) {
	addr, _ := fakeGateway(t)
	_, env := startDaemonWith(t, addr, streamScript, func(c *Config) { c.Audit = failingAudit{} })
	c, _ := NewClient(lookupOf(env))

	resp, err := c.Exec(nil, "status", nil)
	if err != nil || resp.OK || resp.Code != CodeRefused || len(resp.Stdout) != 0 {
		t.Fatalf("exec without audit: %+v %v", resp, err)
	}
	resp, err = c.RunSession(RunRequest{Connection: "openrouter", Command: []string{"true"}})
	if err != nil || resp.OK || resp.Session != nil || resp.Code != CodeRefused {
		t.Fatalf("session without audit: %+v %v", resp, err)
	}
	resp, err = c.Exec(nil, "bogus", nil)
	if err != nil || resp.OK || resp.Code != CodeRefused {
		t.Fatalf("refusal without audit: %+v %v", resp, err)
	}
}

func TestExitOfUnknownRunIsRejected(t *testing.T) {
	_, env := startDaemonWith(t, "", streamScript, nil)
	c, _ := NewClient(lookupOf(env))
	c.SetRun("deadbeef")
	if err := c.ReportExit(0); err != nil {
		t.Fatal(err)
	}
	resp, err := c.roundTrip(Request{Op: OpRunExit, RunID: "deadbeef"})
	if err != nil || resp.OK || resp.Code != CodeNotFound {
		t.Fatalf("resp=%+v err=%v", resp, err)
	}
	(&Client{}).SetRun("")
	if err := (&Client{}).ReportExit(1); err != nil {
		t.Fatalf("no run to report: %v", err)
	}
}

type countingWriter struct {
	n    atomic.Int64
	last atomic.Int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.n.Add(int64(len(p)))
	w.last.Store(int64(len(p)))
	return len(p), nil
}

func TestLargeOutputStreamsWithoutACap(t *testing.T) {
	rec := &recordingAudit{}
	_, env := startDaemonWith(t, "", streamScript, func(c *Config) { c.Audit = rec })
	var out countingWriter
	var errOut bytes.Buffer
	code, handled := Handle(context.Background(), lookupOf(env), []string{"doctor"}, IO{Out: &out, ErrOut: &errOut})
	if !handled || code != 0 {
		t.Fatalf("handled=%v code=%d stderr=%q", handled, code, errOut.String())
	}
	if got := out.n.Load(); got != 24<<20 {
		t.Errorf("received %d bytes, want %d", got, 24<<20)
	}
	if !strings.Contains(errOut.String(), "tail") {
		t.Errorf("stderr = %q", errOut.String())
	}
	waitFor(t, "run.exited", func() bool { return len(rec.byAction(audit.ActionRunExited)) == 1 })
	if got := rec.byAction(audit.ActionRunExited)[0].Extra["bytes_relayed"].(int64); got < 24<<20 {
		t.Errorf("bytes_relayed = %d", got)
	}
}

func TestOutputArrivesBeforeTheVerbEnds(t *testing.T) {
	gate := filepath.Join(t.TempDir(), "gate")
	t.Setenv("GATE", gate)
	_, env := startDaemonWith(t, "", streamScript, nil)

	var mu sync.Mutex
	var seen bytes.Buffer
	w := writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		seen.Write(p)
		if strings.Contains(seen.String(), "one") {
			_ = os.WriteFile(gate, nil, 0o600)
		}
		return len(p), nil
	})
	done := make(chan int, 1)
	go func() {
		code, _ := Handle(context.Background(), lookupOf(env), []string{"list"}, IO{Out: w, ErrOut: io.Discard})
		done <- code
	}()
	select {
	case code := <-done:
		if code != 0 || !strings.Contains(seen.String(), "two") {
			t.Fatalf("code=%d output=%q", code, seen.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("output was held back until the verb ended")
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestStdinReachesTheVerbInteractively(t *testing.T) {
	_, env := startDaemonWith(t, "", streamScript, nil)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan int, 1)
	go func() {
		code, _ := Handle(context.Background(), lookupOf(env), []string{"call"}, IO{In: inR, Out: outW, ErrOut: io.Discard})
		_ = outW.Close()
		done <- code
	}()
	lines := make(chan string, 4)
	go func() {
		buf := make([]byte, 64)
		for {
			n, err := outR.Read(buf)
			if n > 0 {
				lines <- string(buf[:n])
			}
			if err != nil {
				close(lines)
				return
			}
		}
	}()
	expect := func(want string) {
		t.Helper()
		select {
		case got := <-lines:
			if strings.TrimSpace(got) != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("no reply for %q: stdin is not forwarded as it arrives", want)
		}
	}
	_, _ = io.WriteString(inW, "alpha\n")
	expect("got:alpha")
	_, _ = io.WriteString(inW, "beta\n")
	expect("got:beta")
	_ = inW.Close()
	if code := <-done; code != 0 {
		t.Fatalf("exit %d", code)
	}
}

func TestVerbExitStatusIsRelayed(t *testing.T) {
	_, env := startDaemonWith(t, "", streamScript, nil)
	var out, errOut bytes.Buffer
	code, handled := Handle(context.Background(), lookupOf(env), []string{"describe"}, IO{Out: &out, ErrOut: &errOut})
	if !handled || code != 7 {
		t.Fatalf("handled=%v code=%d", handled, code)
	}
}

func TestMissingBinaryIsReported(t *testing.T) {
	_, env := startDaemonWith(t, "", streamScript, func(c *Config) { c.Binary = "/nonexistent/keylatch" })
	var errOut bytes.Buffer
	code, handled := Handle(context.Background(), lookupOf(env), []string{"status"}, IO{Out: io.Discard, ErrOut: &errOut})
	if !handled || code == 0 || !strings.Contains(errOut.String(), "run status") {
		t.Fatalf("handled=%v code=%d stderr=%q", handled, code, errOut.String())
	}
}

func TestClassifyUsesInjectedAncestry(t *testing.T) {
	chain := []llmcontext.Process{{PID: 1, Names: []string{"keylatch"}}, {PID: 2, Names: []string{"codex"}}}
	s := NewServer(Config{Env: lookupOf(nil), Callers: &callerkind.Classifier{Chain: func(int) []llmcontext.Process { return chain }}})
	res := s.classify(Peer{UID: s.uid, PID: os.Getpid()}, Request{})
	if res.Kind != KindAgent || res.Harness != "codex" {
		t.Fatalf("classification = %+v", res)
	}
}

const (
	helperEnv  = "KEYLATCH_TEST_HELPER"
	helperSock = "KEYLATCH_TEST_SOCKET"
	helperBin  = "KEYLATCH_TEST_BIN"
)

// TestHelperHarness stands in for an agent harness: a process named after one
// that starts the real test binary as an unsandboxed child.
func TestHelperHarness(t *testing.T) {
	if os.Getenv(helperEnv) != "harness" {
		t.Skip("helper process")
	}
	cmd := exec.Command(os.Getenv(helperBin), "-test.run=^TestHelperPeer$")
	cmd.Env = append(os.Environ(), helperEnv+"=peer")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "peer:", err)
		os.Exit(1)
	}
}

// TestHelperPeer connects without sending any agent signal and prints how the
// daemon classified it.
func TestHelperPeer(t *testing.T) {
	if os.Getenv(helperEnv) != "peer" {
		t.Skip("helper process")
	}
	c, err := NewClient(lookupOf(map[string]string{"KEYLATCH_SOCKET": os.Getenv(helperSock)}))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Exec(nil, "status", nil)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("KIND=%s\n", resp.Kind)
}

func TestUnsandboxedChildOfAHarnessIsAnAgent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the fake harness relies on /proc process names")
	}
	rec := &recordingAudit{}
	d, env := startDaemonWith(t, "", streamScript, func(c *Config) {
		c.Audit = rec
		c.Callers = &callerkind.Classifier{Chain: llmcontext.ChainOf}
	})

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(t.TempDir(), "claude")
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fake, data, 0o700); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(fake, "-test.run=^TestHelperHarness$")
	cmd.Env = append(os.Environ(), helperEnv+"=harness", helperSock+"="+d.socket, helperBin+"="+self)
	for k := range env {
		cmd.Env = append(cmd.Env, k+"="+env[k])
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "KIND=agent") {
		t.Fatalf("a child of a harness that sent no signals was not classified as an agent:\n%s", out)
	}
	decided := rec.byAction(audit.ActionRunDecided)
	if len(decided) != 1 || decided[0].Extra["harness"] != "claude-code" || decided[0].Extra["caller_kind"] != "agent" {
		t.Fatalf("decision = %+v", decided)
	}
}

func TestHarnessAncestryConstrainsSSHAgentAndKeyOperations(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keys := memoryKeys{"ed": pemOf(t, priv), "aes": bytes.Repeat([]byte{1}, 32)}
	harnessChain := func(int) []llmcontext.Process { return []llmcontext.Process{{PID: 9, Names: []string{"claude"}}} }
	d := startKeyDaemonWith(t, keySeed, keys, func(c *Config) {
		c.Callers = &callerkind.Classifier{Chain: harnessChain}
	})

	sshPub, _ := ssh.NewPublicKey(pub)
	if _, err := dialAgent(t, d).Sign(sshPub, []byte("data")); err != nil {
		t.Fatalf("an agent may still sign with an ssh_agent key: %v", err)
	}
	if !strings.Contains(d.audit.dump(), `"caller_kind":"agent"`) || strings.Contains(d.audit.dump(), `"caller_kind":"human"`) {
		t.Fatalf("the ssh-agent socket did not classify the caller from its ancestry: %s", d.audit.dump())
	}

	d.audit.reset()
	code, _, errOut := runKeyCLI(t, d.env, "", "key", "decrypt", "app-local", "--field", "DATA_KEY")
	if code == 0 || !strings.Contains(errOut, "not available to agent callers") {
		t.Fatalf("decrypt for a caller with a harness ancestor: exit %d %q", code, errOut)
	}
	code, _, errOut = runKeyCLI(t, d.env, "", "key", "allow", "app-local", "--field", "DATA_KEY", "--op", "decrypt", "--alg", "A256GCM")
	if code == 0 {
		t.Fatalf("a caller with a harness ancestor widened the allowlist: %q", errOut)
	}
}
