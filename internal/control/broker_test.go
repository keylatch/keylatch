//go:build !windows

package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// connPair returns the two ends of a connected Unix socket. A pair needs no
// bind, so these tests run where a sandbox forbids listening.
func connPair(t *testing.T) (server, client *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("socket pairs are not permitted here: %v", err)
	}
	ends := make([]*net.UnixConn, 2)
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), "pair")
		c, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		ends[i] = c.(*net.UnixConn)
		t.Cleanup(func() { _ = c.Close() })
	}
	return ends[0], ends[1]
}

// serveOne runs one request through ServeConn and returns the first reply.
func serveOne(t *testing.T, s *Server, peer Peer, frame any) Response {
	t.Helper()
	server, client := connPair(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.ServeConn(context.Background(), server, peer)
		_ = server.Close()
	}()
	b, _ := json.Marshal(frame)
	_, _ = client.Write(append(b, '\n'))
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(client).ReadBytes('\n')
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	<-done
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("decode %q: %v", line, err)
	}
	return resp
}

type echoExtension struct {
	handled bool
	seen    []string
}

func (e *echoExtension) Handle(_ context.Context, conn Conn, p Peer, res callerkind.Result, raw []byte) bool {
	e.seen = append(e.seen, string(raw))
	if !e.handled {
		return false
	}
	_ = writeFrame(conn, Response{OK: true, Kind: res.Kind, Stdout: []byte(p.Cgroup)})
	return true
}

func TestGateRefusesRequestsThatActOnPolicy(t *testing.T) {
	gateErr := errors.New("the stored policy is tampered; the daemon denies")
	var gated []string
	s := NewServer(Config{
		Env: lookupOf(nil),
		Gate: func(_ context.Context, res callerkind.Result) error {
			gated = append(gated, string(res.Kind))
			return gateErr
		},
	})
	for _, frame := range []any{
		Request{Op: OpRunSession, Run: &RunRequest{Connection: "x", Command: []string{"true"}}},
		Request{Op: OpContained, Run: &RunRequest{Connection: "x", Command: []string{"true"}}},
		Request{Op: OpKey, Key: &KeyRequest{Action: "sign", Connection: "x"}},
		Request{Op: OpExec, Verb: "call"},
		Request{Op: OpExec, Verb: "get"},
	} {
		resp := serveOne(t, s, Peer{UID: s.uid, PID: 0}, frame)
		if resp.OK || resp.Code != CodeRefused || !strings.Contains(resp.Error, "tampered") {
			t.Errorf("%+v under a failing gate = %+v", frame, resp)
		}
	}
	if len(gated) != 5 {
		t.Fatalf("the gate ran %d times, want once per request", len(gated))
	}
	// Diagnostics are not gated: the unknown-operation reply proves the request got past it.
	before := len(gated)
	resp := serveOne(t, s, Peer{UID: s.uid}, Request{Op: "nonsense"})
	if resp.Code != CodeBadRequest || len(gated) != before {
		t.Fatalf("an operation that acts on nothing = %+v (gate ran %d more times)", resp, len(gated)-before)
	}
}

func TestGatedOperations(t *testing.T) {
	type gateCase struct {
		Op   Op
		Verb string
	}
	for c, want := range map[gateCase]bool{
		{Op: OpRunSession}:                 true,
		{Op: OpContained}:                  true,
		{Op: OpGateway}:                    true,
		{Op: OpProxy}:                      true,
		{Op: OpCredential}:                 true,
		{Op: OpKey}:                        true,
		{Op: OpKeyPolicy}:                  true,
		{Op: OpExec, Verb: "call"}:         true,
		{Op: OpExec, Verb: "run"}:          true,
		{Op: OpExec, Verb: "mint"}:         true,
		{Op: OpExec, Verb: "status"}:       false,
		{Op: OpExec, Verb: "doctor"}:       false,
		{Op: OpEndSession}:                 false,
		{Op: OpRunExit}:                    false,
		{Op: "presence.begin"}:             false,
		{Op: OpExec, Verb: "policy"}:       false,
		{Op: OpExec, Verb: "list"}:         false,
		{Op: OpExec, Verb: "describe"}:     false,
		{Op: OpExec, Verb: "export"}:       true,
		{Op: OpExec, Verb: "backup"}:       true,
		{Op: OpExec, Verb: "explain"}:      false,
		{Op: OpExec, Verb: "get"}:          true,
		{Op: OpKeyPolicy, Verb: "ignored"}: true,
	} {
		if got := gated(Request{Op: c.Op, Verb: c.Verb}); got != want {
			t.Errorf("gated(%s %s) = %v, want %v", c.Op, c.Verb, got, want)
		}
	}
}

func TestPeerVerifyRefusesAChangedProcess(t *testing.T) {
	s := NewServer(Config{Env: lookupOf(nil)})
	resp := serveOne(t, s, Peer{UID: s.uid, Verify: func() error { return errors.New("the peer process no longer matches its identity") }}, Request{Op: "nonsense"})
	if resp.OK || resp.Code != CodeRefused || !strings.Contains(resp.Error, "no longer matches") {
		t.Fatalf("a peer that changed = %+v", resp)
	}
	calls := 0
	resp = serveOne(t, s, Peer{UID: s.uid, Verify: func() error { calls++; return nil }}, Request{Op: "nonsense"})
	if calls != 1 || resp.Code != CodeBadRequest {
		t.Fatalf("a verified peer = %+v after %d checks", resp, calls)
	}
}

func TestExtensionServesWhatTheProtocolDoesNot(t *testing.T) {
	ext := &echoExtension{handled: true}
	s := NewServer(Config{Env: lookupOf(nil), Extension: ext})
	resp := serveOne(t, s, Peer{UID: s.uid, Cgroup: "/user.slice/x.scope"}, map[string]any{"op": "broker.status"})
	if !resp.OK || string(resp.Stdout) != "/user.slice/x.scope" || len(ext.seen) != 1 || !strings.Contains(ext.seen[0], "broker.status") {
		t.Fatalf("extension reply = %+v, saw %v", resp, ext.seen)
	}
	ext.handled = false
	if resp := serveOne(t, s, Peer{UID: s.uid}, map[string]any{"op": "broker.status"}); resp.Code != CodeBadRequest {
		t.Fatalf("an operation the extension declines = %+v", resp)
	}
}

func TestPeerCgroupAndTicketOverrideClassify(t *testing.T) {
	var verified []string
	s := NewServer(Config{
		Env: lookupOf(nil),
		Callers: &callerkind.Classifier{
			NoHuman:    true,
			AgentScope: func(cg string) bool { return cg == "/agent.scope" },
		},
		Ticket: func(raw string, _ Peer) bool { verified = append(verified, raw); return raw == "good" },
	})
	self := Peer{UID: s.uid, PID: os.Getpid()}
	if got := s.classify(self, Request{}).Kind; got != KindHost {
		t.Errorf("a broker never classifies a peer as human: %s", got)
	}
	inScope := self
	inScope.Cgroup = "/agent.scope"
	if got := s.classify(inScope, Request{}).Kind; got != KindAgent {
		t.Errorf("a peer in a registered scope = %s, want agent", got)
	}
	if got := s.classify(self, Request{Ticket: "good"}).Kind; got != KindAgent {
		t.Errorf("a peer with a genuine ticket = %s, want agent", got)
	}
	if got := s.classify(self, Request{Ticket: "forged"}).Kind; got != KindHost {
		t.Errorf("a peer with a forged ticket = %s, want host", got)
	}
	if len(verified) != 2 {
		t.Errorf("the ticket verifier ran %d times, want 2 (an empty ticket is never checked)", len(verified))
	}
}

func TestChildEnvCarriesThePartition(t *testing.T) {
	s := NewServer(Config{Env: lookupOf(nil), ChildEnv: []string{"KEYLATCH_CONFIG_DIR=/var/lib/keylatch/users/1000/config"}})
	env := s.childEnv(KindHost)
	if !contains(env, "KEYLATCH_CONFIG_DIR=/var/lib/keylatch/users/1000/config") || !contains(env, LocalEnv+"=1") {
		t.Fatalf("child environment lacks the partition: %v", env)
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func TestClientTrustsOnlyTheRightListeners(t *testing.T) {
	prev := lookupBrokerUID
	lookupBrokerUID = func() (uint32, error) { return 4711, nil }
	defer func() { lookupBrokerUID = prev }()

	self := uint32(os.Getuid()) //nolint:gosec // G115: uid is non-negative
	user := &Client{}
	for uid, want := range map[uint32]bool{self: true, 0: true, 4711: false, 31337: false} {
		if got := user.trusted(uid); got != want {
			t.Errorf("user-level client trusts %d = %v, want %v", uid, got, want)
		}
	}
	broker := &Client{broker: true}
	for uid, want := range map[uint32]bool{self: true, 0: true, 4711: true, 31337: false} {
		if got := broker.trusted(uid); got != want {
			t.Errorf("broker client trusts %d = %v, want %v", uid, got, want)
		}
	}
	lookupBrokerUID = func() (uint32, error) { return 0, errors.New("no such user") }
	if broker.trusted(4711) {
		t.Error("a broker account that cannot be resolved must not be trusted")
	}
	if !broker.Broker() || user.Broker() {
		t.Error("Broker() must report which socket the client uses")
	}
}

func TestBrokerInstalledNeedsASocket(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "broker.sock")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	env := func(overrides map[string]string) llmcontext.Lookup {
		return func(k string) string { return overrides[k] }
	}
	if BrokerInstalled(env(map[string]string{"KEYLATCH_BROKER_SOCKET": regular})) {
		t.Error("a regular file is not a broker socket")
	}
	if BrokerInstalled(env(map[string]string{"KEYLATCH_BROKER_SOCKET": filepath.Join(dir, "absent")})) {
		t.Error("a missing socket is not a broker")
	}
	if BrokerInstalled(env(map[string]string{"KEYLATCH_BROKER_SOCKET": regular, "KEYLATCH_SOCKET": "/elsewhere"})) {
		t.Error("naming a user-level socket must disable the broker")
	}
	if isSocket(dir) {
		t.Error("a directory is not a socket")
	}
}

func TestIsPolicyCheck(t *testing.T) {
	for _, tc := range []struct {
		verb string
		rest []string
		want bool
	}{
		{"policy", []string{"check", "github", "--as", "agent"}, true},
		{"policy", []string{"import", "dir"}, false},
		{"policy", nil, false},
		{"status", []string{"check"}, false},
	} {
		if got := isPolicyCheck(tc.verb, tc.rest); got != tc.want {
			t.Errorf("isPolicyCheck(%s %v) = %v", tc.verb, tc.rest, got)
		}
	}
}

// startBrokerSocket serves handler on a fresh Unix socket, or skips where the
// sandbox forbids binding.
func startBrokerSocket(t *testing.T, handler func(brokerapi.Request) brokerapi.Response) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "kl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "broker.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("binding Unix sockets is not permitted here: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				line, err := bufio.NewReader(c).ReadBytes('\n')
				if err != nil {
					return
				}
				req, err := brokerapi.Decode(line)
				if err != nil {
					return
				}
				b, _ := json.Marshal(handler(req))
				_, _ = c.Write(append(b, '\n'))
			}()
		}
	}()
	return path
}

func TestClientPrefersTheBrokerSocket(t *testing.T) {
	var got brokerapi.Request
	path := startBrokerSocket(t, func(r brokerapi.Request) brokerapi.Response {
		got = r
		return brokerapi.Response{OK: true, Status: &brokerapi.Status{Mode: "broker"}}
	})
	env := lookupOf(map[string]string{"KEYLATCH_BROKER_SOCKET": path, "KEYLATCH_AGENT_SESSION": "1"})
	c, err := NewClient(env)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if !c.Broker() || c.Socket() != path {
		t.Fatalf("client uses %s (broker=%v), want %s", c.Socket(), c.Broker(), path)
	}
	resp, err := c.Call(brokerapi.Request{Op: brokerapi.OpStatus})
	if err != nil || !resp.OK || resp.Status.Mode != "broker" {
		t.Fatalf("Call = %+v, %v", resp, err)
	}
	if len(got.Signals) == 0 {
		t.Fatal("the client's agent signals must ride along so the daemon can only get stricter")
	}

	// A raw client sends none of its own and keeps the ticket a request names:
	// the ticket verifier uses it, and classifying would call the verifier again.
	raw, err := NewRawClient(env)
	if err != nil {
		t.Fatalf("NewRawClient: %v", err)
	}
	if _, err := raw.Call(brokerapi.Request{Op: brokerapi.OpSessionVerify, Ticket: "ticket-under-test"}); err != nil {
		t.Fatal(err)
	}
	if len(got.Signals) != 0 || got.Ticket != "ticket-under-test" {
		t.Fatalf("raw request carried signals %v and ticket %q", got.Signals, got.Ticket)
	}
	// KEYLATCH_SOCKET names a user-level socket and wins.
	other := lookupOf(map[string]string{"KEYLATCH_BROKER_SOCKET": path, "KEYLATCH_SOCKET": filepath.Join(filepath.Dir(path), "none.sock")})
	if _, err := NewClient(other); !errors.Is(err, ErrNoDaemon) {
		t.Fatalf("an explicit user-level socket that is absent = %v, want ErrNoDaemon", err)
	}
}

func TestBrokerSocketThatDoesNotAnswerFailsClosed(t *testing.T) {
	dir, err := os.MkdirTemp("", "kl")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "broker.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Skipf("binding Unix sockets is not permitted here: %v", err)
	}
	ln.SetUnlinkOnClose(false)
	_ = ln.Close() // the file stays, nobody listens
	env := lookupOf(map[string]string{"KEYLATCH_BROKER_SOCKET": path})
	if _, err := NewClient(env); !errors.Is(err, ErrBrokerUnreachable) {
		t.Fatalf("NewClient = %v, want ErrBrokerUnreachable", err)
	}
	var out, errOut strings.Builder
	code, handled := Handle(context.Background(), env, []string{"status"}, IO{Out: &out, ErrOut: &errOut})
	if !handled || code == 0 || !strings.Contains(errOut.String(), "does not answer") {
		t.Fatalf("Handle = %d handled=%v stderr=%q: with a broker installed nothing may fall back to local files", code, handled, errOut.String())
	}
}
