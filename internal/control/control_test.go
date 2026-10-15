//go:build !windows

package control

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/registry"
)

type testDaemon struct {
	socket string
	state  string
	lookup func(map[string]string) llmcontext.Lookup
}

func lookupOf(m map[string]string) llmcontext.Lookup {
	return func(k string) string { return m[k] }
}

func startDaemon(t *testing.T, gatewayAddr string) (*testDaemon, map[string]string) {
	t.Helper()
	return startDaemonWith(t, gatewayAddr, "", nil)
}

// startDaemonWith starts a daemon whose served verbs run script (the default
// echoes its arguments) after tune has adjusted the configuration.
func startDaemonWith(t *testing.T, gatewayAddr, script string, tune func(*Config)) (*testDaemon, map[string]string) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "kl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(filepath.Join(state, "gateway"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "gateway", "signing.key"), bytes.Repeat([]byte{7}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(dir, "keylatch")
	if script == "" {
		script = "#!/bin/sh\necho \"args:$*\"\necho \"local:$KEYLATCH_LOCAL agent:$KEYLATCH_AGENT_SESSION\"\nexit ${FAKE_EXIT:-0}\n"
	}
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	socket := filepath.Join(dir, "s", "k.sock")
	env := map[string]string{
		"KEYLATCH_CONFIG_DIR":   state,
		"KEYLATCH_SOCKET":       socket,
		"KEYLATCH_GATEWAY_ADDR": gatewayAddr,
	}
	if err := registry.InitFromConfig(context.Background(), lookupOf(env)); err != nil {
		t.Fatal(err)
	}

	ln, err := Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		cfg := Config{Env: lookupOf(env), Binary: fake}
		if tune != nil {
			tune(&cfg)
		}
		_ = NewServer(cfg).Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return &testDaemon{socket: socket, state: state}, env
}

func TestExecServedVerbForHuman(t *testing.T) {
	_, env := startDaemon(t, "")
	var out, errOut bytes.Buffer
	code, handled := Handle(context.Background(), lookupOf(env), []string{"--json", "status", "--namespace", "x"}, IO{Out: &out, ErrOut: &errOut})
	if !handled || code != 0 {
		t.Fatalf("handled=%v code=%d stderr=%q", handled, code, errOut.String())
	}
	for _, want := range []string{"args:--json status --namespace x", "local:1 agent:"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output %q missing %q", out.String(), want)
		}
	}
}

func TestExecRunsAsAgentSessionWhenSignalsPresent(t *testing.T) {
	_, env := startDaemon(t, "")
	env["KEYLATCH_AGENT_SESSION"] = "1"
	var out, errOut bytes.Buffer
	code, handled := Handle(context.Background(), lookupOf(env), []string{"doctor"}, IO{Out: &out, ErrOut: &errOut})
	if !handled || code != 0 {
		t.Fatalf("handled=%v code=%d stderr=%q", handled, code, errOut.String())
	}
	if !strings.Contains(out.String(), "agent:1") {
		t.Errorf("served verb did not run as an agent session: %q", out.String())
	}
}

func TestValueVerbRefusedForAgent(t *testing.T) {
	_, env := startDaemon(t, "")
	env["KEYLATCH_AGENT_SESSION"] = "1"
	for _, verb := range []string{"get", "export", "backup", "mint"} {
		var out, errOut bytes.Buffer
		code, handled := Handle(context.Background(), lookupOf(env), []string{verb, "svc", "key"}, IO{Out: &out, ErrOut: &errOut})
		if !handled || code != 2 {
			t.Errorf("%s: handled=%v code=%d, want handled with exit 2", verb, handled, code)
		}
		if out.Len() != 0 || !strings.Contains(errOut.String(), "not available to agent callers") {
			t.Errorf("%s: stdout=%q stderr=%q", verb, out.String(), errOut.String())
		}
	}
}

func TestValueVerbRunsLocallyForHuman(t *testing.T) {
	_, env := startDaemon(t, "")
	var out, errOut bytes.Buffer
	if _, handled := Handle(context.Background(), lookupOf(env), []string{"get", "svc", "key"}, IO{Out: &out, ErrOut: &errOut}); handled {
		t.Fatalf("a human's get must fall through to local execution, got %q %q", out.String(), errOut.String())
	}
}

func TestUnservedVerbAndBareRunRejected(t *testing.T) {
	d, env := startDaemon(t, "")
	c, err := NewClient(lookupOf(env))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		verb string
		args []string
	}{{"setup", nil}, {"run", []string{"openrouter", "--", "true"}}} {
		resp, err := c.Exec(nil, tc.verb, tc.args)
		if err != nil {
			t.Fatal(err)
		}
		if resp.OK || resp.Code != CodeBadRequest {
			t.Errorf("%s: resp=%+v", tc.verb, resp)
		}
	}
	_ = d
}

func TestNoDaemonFallsBackToLocal(t *testing.T) {
	env := map[string]string{"KEYLATCH_SOCKET": "/tmp/klmissing/none.sock"}
	if _, handled := Handle(context.Background(), lookupOf(env), []string{"status"}, IO{Out: io.Discard, ErrOut: io.Discard}); handled {
		t.Fatal("status must run locally when no daemon answers")
	}
}

func TestLocalOverrideBypassesDaemon(t *testing.T) {
	_, env := startDaemon(t, "")
	env[LocalEnv] = "1"
	if _, handled := Handle(context.Background(), lookupOf(env), []string{"status"}, IO{Out: io.Discard, ErrOut: io.Discard}); handled {
		t.Fatal("KEYLATCH_LOCAL=1 must skip the daemon")
	}
}

func TestListenReplacesStaleSocketAndRejectsLiveOne(t *testing.T) {
	d, _ := startDaemon(t, "")
	if _, err := Listen(d.socket); err == nil {
		t.Fatal("a second daemon on a live socket must be refused")
	}
	info, err := os.Stat(d.socket)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("socket mode = %v, want 0600", info.Mode().Perm())
	}

	stale := filepath.Join(filepath.Dir(d.socket), "stale.sock")
	l, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = l.Close()
	ln, err := Listen(stale)
	if err != nil {
		t.Fatalf("stale socket was not replaced: %v", err)
	}
	_ = ln.Close()
}

func fakeGateway(t *testing.T) (addr string, auth chan string) {
	t.Helper()
	auth = make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth <- r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "gateway-reached")
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), auth
}

func TestRunSessionKeepsProviderKeyOutOfChild(t *testing.T) {
	addr, _ := fakeGateway(t)
	_, env := startDaemon(t, addr)
	t.Setenv("OPENROUTER_API_KEY", "sk-or-real-provider-key")
	t.Setenv("KEYLATCH_STATE_HINT", "must-not-leak")

	var out, errOut bytes.Buffer
	code, handled := Handle(context.Background(), lookupOf(env),
		[]string{"run", "--tier", "d2", "openrouter", "--", "sh", "-c", `printf "%s|%s|%s|%s|%s" "$OPENROUTER_API_KEY" "$KEYLATCH_GATEWAY_URL" "$KEYLATCH_GATEWAY_TOKEN" "$KEYLATCH_RUNTIME" "$KEYLATCH_STATE_HINT"`},
		IO{In: strings.NewReader(""), Out: &out, ErrOut: &errOut})
	if !handled || code != 0 {
		t.Fatalf("handled=%v code=%d stderr=%q", handled, code, errOut.String())
	}
	parts := strings.Split(out.String(), "|")
	if len(parts) != 5 {
		t.Fatalf("unexpected child output %q", out.String())
	}
	if parts[0] != "" || parts[4] != "" {
		t.Errorf("provider key or Keylatch configuration reached the child: %q", out.String())
	}
	if !strings.HasPrefix(parts[1], "http://127.0.0.1:") || strings.Contains(parts[1], addr) {
		t.Errorf("gateway URL %q must point at the local forwarder, not %s", parts[1], addr)
	}
	if strings.Count(parts[2], ".") != 2 || parts[3] != "gateway_typed" {
		t.Errorf("token %q runtime %q", parts[2], parts[3])
	}
}

func TestRunSessionReachesGatewayThroughForwarder(t *testing.T) {
	addr, auth := fakeGateway(t)
	_, env := startDaemon(t, addr)

	c, err := NewClient(lookupOf(env))
	if err != nil {
		t.Fatal(err)
	}
	fwd, stop, err := c.Forward()
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	req, _ := http.NewRequest(http.MethodGet, "http://"+fwd+"/", nil)
	req.Header.Set("Authorization", "Bearer probe")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "gateway-reached" || <-auth != "Bearer probe" {
		t.Fatalf("forwarder did not relay the request: %q", body)
	}
}

func TestRunSessionPolicy(t *testing.T) {
	addr, _ := fakeGateway(t)
	_, env := startDaemon(t, addr)
	c, err := NewClient(lookupOf(env))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		req  RunRequest
		code string
	}{
		{"uncontained tier", RunRequest{Connection: "openrouter", Command: []string{"true"}, Tier: TierRaw}, CodeRefused},
		{"unbuilt tier", RunRequest{Connection: "openrouter", Command: []string{"true"}, Tier: TierPlaceholder}, CodeUnavailable},
		{"unknown connection", RunRequest{Connection: "nope", Command: []string{"true"}}, CodeNotFound},
		{"wrong runtime", RunRequest{Connection: "openrouter", Command: []string{"true"}, Runtime: "direct_brokered"}, CodeBadRequest},
		{"no command", RunRequest{Connection: "openrouter"}, CodeBadRequest},
	} {
		resp, err := c.RunSession(tc.req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.OK || resp.Code != tc.code || resp.Session != nil {
			t.Errorf("%s: resp=%+v, want code %s", tc.name, resp, tc.code)
		}
	}
}

func TestRunSessionNeedsRunningGateway(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	_, env := startDaemon(t, addr)
	c, _ := NewClient(lookupOf(env))
	resp, err := c.RunSession(RunRequest{Connection: "openrouter", Command: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.OK || resp.Code != CodeUnavailable || !strings.Contains(resp.Error, "gateway is not running") {
		t.Fatalf("resp=%+v", resp)
	}
}

func TestClassify(t *testing.T) {
	s := NewServer(Config{Env: lookupOf(nil)})
	self := Peer{UID: s.uid, PID: os.Getpid()}
	if got := s.classify(self, Request{}).Kind; got != KindHuman {
		t.Errorf("same-namespace peer without signals = %s, want human", got)
	}
	if got := s.classify(self, Request{Signals: []string{"CLAUDECODE"}}).Kind; got != KindAgent {
		t.Errorf("peer with a signal = %s, want agent", got)
	}
	if got := s.classify(Peer{UID: s.uid, PID: 0}, Request{}).Kind; got != KindHost {
		t.Errorf("peer outside the daemon's namespaces = %s, want host", got)
	}
}

func TestParseRunArgs(t *testing.T) {
	ra, err := parseRunArgs([]string{"--runtime=gateway_sdk", "--tier", "d2", "--clean-env", "--extra", "A,B", "conn", "--", "cmd", "--flag"})
	if err != nil {
		t.Fatal(err)
	}
	if ra.connection != "conn" || ra.runtime != "gateway_sdk" || ra.tier != TierGateway || !ra.clean ||
		strings.Join(ra.extra, ",") != "A,B" || strings.Join(ra.command, " ") != "cmd --flag" {
		t.Errorf("parsed %+v", ra)
	}
	for _, bad := range [][]string{
		{"conn"},
		{"conn", "--"},
		{"--", "cmd"},
		{"--allow", "x", "conn", "--", "cmd"},
		{"--extra", "KEYLATCH_HOME", "conn", "--", "cmd"},
		{"a", "b", "--", "cmd"},
	} {
		if _, err := parseRunArgs(bad); err == nil {
			t.Errorf("parseRunArgs(%v) accepted", bad)
		}
	}
}
