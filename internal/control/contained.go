package control

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/canary"
	"github.com/keylatch/keylatch/internal/contained"
	"github.com/keylatch/keylatch/internal/egress"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/policy/connpolicy"
	"github.com/keylatch/keylatch/internal/redactor"
	"github.com/keylatch/keylatch/internal/registry"
)

// containedRuntime is the runtime name reported for tier D5.
const containedRuntime = "contained"

// containedMaxRun bounds one contained run unless the policy sets a shorter one.
const containedMaxRun = 30 * time.Minute

// ContainedConfig serves tier D5: the daemon starts the child in a Keylatch
// sandbox, hands it the real value and relays its output through a redactor.
// Without it D5 is refused.
type ContainedConfig struct {
	Launcher contained.Launcher
	// Values returns the stored value of a connection's field. The caller wipes it.
	Values func(ctx context.Context, connection, field string) ([]byte, error)
	// StateDir holds each run's private directories. It must not be readable by
	// other users.
	StateDir string
	// ReadOnly lists toolchain caches the sandbox may read in every run.
	ReadOnly []string
	// DenyPaths are host paths no run may touch, on top of the built-in list of
	// Keylatch state, SSH keys and cloud credentials.
	DenyPaths []string
	// Listen opens the egress socket the sandbox's forwarder connects to; nil
	// listens on a Unix socket at the path.
	Listen func(path string) (net.Listener, error)
	// Resolver and Dial replace DNS and the network for the egress proxy.
	Resolver egress.Resolver
	Dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	// Report describes what the host allows; it is quoted in refusals.
	Report func() contained.Report
}

// ApprovalRequest is everything one approval is bound to. An approval for one
// argv, tier, host set or lifetime never applies to another.
type ApprovalRequest struct {
	Connection string
	Tier       Tier
	Argv       []string
	Hosts      []string
	TTL        time.Duration
	Caller     Kind
	// Plan is the human-readable plan the approver shows.
	Plan string
	// Project is the directory a contained run may write.
	Project string
	// Notify tells the waiting caller what to do, for example which command
	// answers the approval. It is nil when the caller has no stream.
	Notify func(string)
}

// ArgvDigest is the SHA-256 of the exact argv.
func (a ApprovalRequest) ArgvDigest() string { return digest(a.Argv...) }

// Approver obtains approval for a run, returning an identifier that is audited.
type Approver func(ctx context.Context, req ApprovalRequest) (id string, err error)

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// passthroughEnv are the client variables forwarded to a contained child
// without being asked for: terminal and locale settings.
var passthroughEnv = []string{"TERM", "COLORTERM", "LANG", "TZ", "NO_COLOR", "FORCE_COLOR", "CI"}

type refusal struct {
	code string
	exit int
	msg  string
}

type containedPlan struct {
	tmpl     registry.ConnectionTemplate
	hosts    []string
	project  string
	spec     contained.Spec
	maxRun   time.Duration
	approval string
}

// denyList is every host path a contained run must never be given, whatever
// the policy or the caller asks for: Keylatch state and run directories, SSH
// keys, cloud and container credentials, browser profiles and the agents' own
// configuration.
func (s *Server) denyList(extra ...string) []string {
	list := append([]string{paths.ConfigDir(s.cfg.Env)}, extra...)
	if home, err := os.UserHomeDir(); err == nil {
		for _, p := range []string{".ssh", ".aws", ".config/gcloud", ".kube", ".gnupg", ".config/keylatch", ".keylatch",
			".mozilla", ".config/google-chrome", ".config/chromium", ".config/BraveSoftware", ".claude", ".codex", ".gemini", ".docker"} {
			list = append(list, filepath.Join(home, p))
		}
	}
	if s.cfg.Contained != nil {
		list = append(list, s.cfg.Contained.DenyPaths...)
		list = append(list, s.cfg.Contained.StateDir)
	}
	return slices.DeleteFunc(list, func(p string) bool { return p == "" })
}

// within reports whether path is dir or below it.
func within(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

// reaches reports whether a bind of path would expose dir: path is dir, below
// it, or an ancestor that contains it.
func reaches(path, dir string) bool { return within(path, dir) || within(dir, path) }

func realPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

// planContained validates a request and prepares the sandbox, without starting
// anything or reading a secret.
func (s *Server) planContained(ctx context.Context, kind Kind, rr *RunRequest) (*containedPlan, *refusal) {
	deny := func(code string, exit int, format string, a ...any) (*containedPlan, *refusal) {
		return nil, &refusal{code, exit, fmt.Sprintf(format, a...)}
	}
	cc := s.cfg.Contained
	if cc == nil || cc.Launcher == nil || cc.Values == nil {
		return deny(CodeUnavailable, exitcode.RuntimeNotAvailable, "tier D5 is not available: this daemon has no sandbox launcher")
	}
	if rr == nil || rr.Connection == "" || len(rr.Command) == 0 {
		return deny(CodeBadRequest, exitcode.UserError, "a connection and a command are required")
	}
	if rr.Runtime != "" && rr.Runtime != containedRuntime {
		return deny(CodeBadRequest, exitcode.UserError, "tier D5 does not take the %s runtime", rr.Runtime)
	}
	for _, a := range rr.Command {
		if strings.ContainsRune(a, 0) {
			return deny(CodeBadRequest, exitcode.UserError, "argument contains a NUL byte")
		}
	}
	tmpl, err := s.template(ctx, rr.Connection)
	if err != nil {
		return deny(CodeNotFound, exitcode.Missing, "unknown connection %q", rr.Connection)
	}
	if len(tmpl.InjectionRules) == 0 {
		return deny(CodeBadRequest, exitcode.UserError, "connection %q declares no environment variables to inject", rr.Connection)
	}
	if len(tmpl.MintedFields) > 0 {
		return deny(CodeRefused, exitcode.PolicyDeny, "connection %q mints its credential, which only tier D3 delivers", rr.Connection)
	}
	dec, f := s.gateTier(ctx, kind, rr, TierContained, true)
	if f != nil {
		return nil, f
	}
	if rr.CWD == "" {
		return deny(CodeBadRequest, exitcode.UserError, "the working directory is required")
	}
	project, err := realPath(rr.CWD)
	if err != nil {
		return deny(CodeBadRequest, exitcode.UserError, "working directory: %v", err)
	}
	if info, err := os.Stat(project); err != nil || !info.IsDir() || project == "/" {
		return deny(CodeRefused, exitcode.PolicyDeny, "%s cannot be the project of a contained run", project)
	}
	vars := s.pathVars(project)
	policyDeny := expandPaths(dec.FSDeny, vars)
	for _, d := range s.denyList(policyDeny...) {
		if resolved, err := realPath(d); err == nil {
			d = resolved
		}
		if reaches(project, d) {
			return deny(CodeRefused, exitcode.PolicyDeny, "%s is not available to contained runs", project)
		}
	}
	// A write list that expands to nothing allows nothing; it does not lift the
	// limit.
	if len(dec.FSWrite) > 0 && !connpolicy.WithinAny(project, expandPaths(dec.FSWrite, vars)) {
		return deny(CodeRefused, exitcode.PolicyDeny, "policy does not allow writes under %s", project)
	}
	if dec.HostWriteRestricted && !connpolicy.WithinAny(project, expandPaths(dec.HostWrite, vars)) {
		return deny(CodeRefused, exitcode.PolicyDeny, "the host sandbox does not allow writes under %s", project)
	}
	readOnly, err := s.readOnlyPaths(cc, expandPaths(dec.FSRead, vars), policyDeny)
	if err != nil {
		return deny(CodeRefused, exitcode.PolicyDeny, "%v", err)
	}

	var hosts []string
	if b, ok := tmpl.Binding(); ok {
		hosts = connpolicy.IntersectHostsIfAny(b.Hosts, dec.Hosts)
	}
	hosts = append(hosts, dec.EgressAllow...)
	slices.Sort(hosts)
	hosts = slices.Compact(hosts)

	maxRun := containedMaxRun
	if dec.MaxTTL > 0 {
		maxRun = min(maxRun, dec.MaxTTL)
	}
	return &containedPlan{
		tmpl: tmpl, hosts: hosts, project: project, maxRun: maxRun, approval: dec.Approval,
		spec: contained.Spec{
			Argv: rr.Command, Project: project, ReadOnly: readOnly,
			Limits: contained.Limits{MemoryBytes: 4 << 30, PIDs: 1024},
			TTY:    rr.TTY,
		},
	}, nil
}

// readOnlyPaths is the daemon's list of toolchain caches plus the policy's read
// paths, each resolved and checked against the deny list.
func (s *Server) readOnlyPaths(cc *ContainedConfig, policyRead, policyDeny []string) ([]string, error) {
	var out []string
	for _, p := range slices.Concat(cc.ReadOnly, policyRead) {
		resolved, err := realPath(p)
		if err != nil {
			continue
		}
		for _, d := range s.denyList(policyDeny...) {
			if r, err := realPath(d); err == nil {
				d = r
			}
			if reaches(resolved, d) {
				return nil, fmt.Errorf("policy allows reading %s, which holds credentials and is never mounted", p)
			}
		}
		out = append(out, resolved)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// environment builds the child's whole environment. Nothing of the caller's
// carries over except terminal settings and names it asked for.
func containedEnv(rr *RunRequest, secrets map[string][]byte, home string) []string {
	set := map[string]string{
		"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": home, "TMPDIR": "/tmp",
		"NODE_USE_ENV_PROXY": "1", "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost",
		"KEYLATCH_RUNTIME": containedRuntime,
	}
	proxy := fmt.Sprintf("http://127.0.0.1:%d", contained.DefaultProxyPort)
	for _, n := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		set[n] = proxy
	}
	offered := map[string]string{}
	for _, e := range rr.Env {
		if name, value, ok := strings.Cut(e, "="); ok && envName.MatchString(name) && !strings.HasPrefix(name, "KEYLATCH_") {
			offered[name] = value
		}
	}
	for name, value := range offered {
		if slices.Contains(passthroughEnv, name) || strings.HasPrefix(name, "LC_") || (name != "PATH" && name != "HOME" && !strings.HasSuffix(strings.ToUpper(name), "_PROXY")) {
			set[name] = value
		}
	}
	for name, value := range secrets {
		set[name] = string(value)
	}
	env := make([]string, 0, len(set))
	for name, value := range set {
		env = append(env, name+"="+value)
	}
	slices.Sort(env)
	return env
}

// planDigest identifies the sandbox a run was given without exposing its
// environment: the command, project, paths, hosts and limits.
func planDigest(p *containedPlan) string {
	parts := slices.Concat(p.spec.Argv, []string{"--", p.project}, p.spec.ReadOnly, []string{"--"}, p.hosts)
	parts = append(parts, fmt.Sprint(p.spec.Limits), fmt.Sprint(p.spec.TTY != nil))
	return digest(parts...)
}

func hostList(hosts []string) string {
	if len(hosts) == 0 {
		return "none"
	}
	return strings.Join(hosts, ", ")
}

// containedRun serves one OpContained request: it decides, starts the sandbox
// and relays its output until the child ends.
func (s *Server) containedRun(ctx context.Context, conn Conn, r *bufio.Reader, res callerkind.Result, req Request) {
	kind := res.Kind
	rr := req.Run
	d := decision{op: string(OpContained), res: res, child: childInDaemon, tier: TierContained}
	if rr != nil {
		d.connection, d.argv, d.cwd = rr.Connection, rr.Command, rr.CWD
	}
	var mu sync.Mutex
	send := func(resp Response) {
		mu.Lock()
		defer mu.Unlock()
		_ = writeFrame(conn, resp)
	}
	finish := func(resp Response, outcome audit.Outcome) {
		resp.Kind = kind
		if err := s.record(ctx, d, outcome); err != nil {
			resp = auditRefusal(resp, err)
		}
		send(resp)
	}
	refuse := func(f refusal) {
		d.reason = f.msg
		finish(Response{Code: f.code, ExitCode: f.exit, Error: f.msg}, audit.OutcomeDenied)
	}

	plan, f := s.planContained(ctx, kind, rr)
	if f != nil {
		refuse(*f)
		return
	}
	d.hosts = plan.hosts
	d.sandbox = planDigest(plan)

	notify := func(msg string) { send(Response{Kind: kind, More: true, Stderr: []byte(msg)}) }
	if err := s.approveContained(ctx, kind, rr, plan, &d, notify); err != nil {
		refuse(*err)
		return
	}

	secrets := map[string][]byte{}
	defer func() {
		for _, v := range secrets {
			clear(v)
		}
	}()
	var values [][]byte
	for _, rule := range plan.tmpl.InjectionRules {
		v, err := s.cfg.Contained.Values(ctx, rr.Connection, rule.Source)
		if err != nil {
			refuse(refusal{CodeUnavailable, exitcode.OperationFailed, fmt.Sprintf("could not read %s.%s from the store", rr.Connection, rule.Source)})
			return
		}
		secrets[rule.EnvVar] = v
		values = append(values, v)
	}
	decoys, err := canary.NewSet(rr.Connection)
	if err != nil {
		refuse(refusal{CodeUnavailable, exitcode.OperationFailed, "could not prepare the sandbox: " + err.Error()})
		return
	}
	for _, v := range decoys.Values {
		values = append(values, []byte(v))
	}
	matcher := redactor.NewMatcher(values...)
	decoyed := redactor.NewMatcher(stringBytes(decoys.Values)...)

	runDir, err := s.newRunDir()
	if err != nil {
		refuse(refusal{CodeUnavailable, exitcode.OperationFailed, "could not prepare the sandbox: " + err.Error()})
		return
	}
	defer func() { _ = os.RemoveAll(runDir) }()
	egressDir, rootDir := filepath.Join(runDir, "e"), filepath.Join(runDir, "r")
	for _, p := range []string{egressDir, rootDir} {
		if err := os.Mkdir(p, 0o700); err != nil {
			refuse(refusal{CodeUnavailable, exitcode.OperationFailed, "could not prepare the sandbox: " + err.Error()})
			return
		}
	}

	d.runID = newRunID()
	if err := s.record(ctx, d, audit.OutcomeOK); err != nil {
		send(auditRefusal(Response{Kind: kind}, err))
		return
	}

	runCtx, cancel := context.WithTimeout(ctx, plan.maxRun)
	defer cancel()
	var tripped atomic.Bool
	proxy := &egress.Proxy{
		Policy:   egress.Policy{Allow: plan.hosts},
		Resolver: s.cfg.Contained.Resolver,
		Dial:     s.cfg.Contained.Dial,
		OnDeny: func(host, reason string) {
			s.emitEgressDenied(ctx, rr.Connection, host, reason)
		},
		Canary: decoyed.Contains,
		OnCanary: func(host, where string) {
			// The first request that carries a decoy ends the run: nothing
			// legitimate holds one, so everything after it is suspect.
			if tripped.CompareAndSwap(false, true) {
				// The decoy may be the host name itself; it is never logged.
				s.emitCanaryTripped(ctx, d, string(decoyed.Redact([]byte(host))), where)
				cancel()
			}
		},
	}
	listen := s.cfg.Contained.Listen
	if listen == nil {
		listen = func(path string) (net.Listener, error) { return net.Listen("unix", path) }
	}
	ln, err := listen(filepath.Join(egressDir, contained.EgressSocket))
	if err != nil {
		s.recordExit(ctx, d.op, "", d.runID, exitcode.OperationFailed, time.Now(), 0, "sandbox egress socket")
		send(Response{Kind: kind, Code: CodeUnavailable, ExitCode: exitcode.OperationFailed, Error: "could not open the sandbox egress socket: " + err.Error()})
		return
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go proxy.ServeConn(c)
		}
	}()

	spec := plan.spec
	spec.Env = containedEnv(rr, secrets, contained.DefaultHome)
	for name, v := range decoys.Env {
		spec.Env = append(spec.Env, name+"="+v)
	}
	for _, f := range decoys.Files {
		spec.Honey = append(spec.Honey, contained.HoneyFile{Path: f.Path, Content: f.Content})
	}
	spec.EgressDir, spec.RootDir, spec.Dir = egressDir, rootDir, plan.project

	snapshot, snapErr := redactor.TakeSnapshot(plan.project)
	begun := time.Now()
	child, err := s.cfg.Contained.Launcher.Start(spec)
	if err != nil {
		msg := "could not start the sandbox: " + err.Error()
		if s.cfg.Contained.Report != nil {
			if missing := s.cfg.Contained.Report().Missing(); len(missing) > 0 {
				msg += " (missing: " + strings.Join(missing, "; ") + ")"
			}
		}
		s.recordExit(ctx, d.op, "", d.runID, exitcode.RuntimeNotAvailable, begun, 0, "sandbox unavailable")
		send(Response{Kind: kind, Code: CodeUnavailable, ExitCode: exitcode.RuntimeNotAvailable, Error: msg})
		return
	}
	if err := writeFrame(conn, Response{OK: true, Kind: kind, More: true, Session: &Session{Tier: TierContained, Runtime: containedRuntime, RunID: d.runID, TTLSeconds: int(plan.maxRun.Seconds())}}); err != nil {
		child.Kill()
		_, _ = child.Wait()
		return
	}

	var relayed, redactions atomic.Int64
	var wg sync.WaitGroup
	drain := func(src io.Reader, stderr bool) {
		defer wg.Done()
		if src == nil {
			return
		}
		fw := &frameWriter{conn: conn, mu: &mu, stderr: stderr, n: &relayed, cancel: cancel}
		rw := matcher.NewWriter(fw)
		_, _ = io.Copy(rw, src)
		_ = rw.Close()
		redactions.Add(int64(rw.Matches()))
		if c, ok := src.(io.Closer); ok {
			_ = c.Close()
		}
	}
	wg.Add(2)
	go drain(child.Stdout(), false)
	go drain(child.Stderr(), true)
	go s.feedContained(r, child, cancel)
	go func() {
		<-runCtx.Done()
		child.Kill()
	}()

	code, waitErr := child.Wait()
	cancel()
	wg.Wait()
	_ = child.Stdin().Close()

	resp := Response{Kind: kind, OK: code == 0 && waitErr == nil, ExitCode: code}
	if waitErr != nil {
		resp.Code, resp.Error, resp.ExitCode = CodeUnavailable, "sandbox: "+waitErr.Error(), exitcode.OperationFailed
	}
	reason := ""
	if snapErr == nil {
		if findings, err := matcher.ScanChanged(snapshot, redactor.ScanReport); err == nil && len(findings) > 0 {
			s.emitLeakSuspected(ctx, d, len(findings))
			resp.OK, resp.ExitCode, resp.Code = false, exitcode.PolicyDeny, CodeRefused
			resp.Error = fmt.Sprintf("a secret value (or an encoding of it) was written to %d file(s) under %s; see %s", len(findings), plan.project, findingPaths(findings, plan.project))
			reason = "leak_suspected"
		}
	}
	if tripped.Load() {
		resp.OK, resp.ExitCode, resp.Code = false, exitcode.SecurityBlock, CodeRefused
		resp.Error = "a canary credential was sent out of the sandbox; the run was ended"
		reason = "canary_tripped"
	}
	// The exit is audited before the final frame so a client that has seen
	// the end of the run can rely on the record being there.
	s.recordContainedExit(ctx, d, begun, resp.ExitCode, relayed.Load(), redactions.Load(), reason)
	mu.Lock()
	_ = writeFrame(conn, resp)
	mu.Unlock()
}

func (s *Server) recordContainedExit(ctx context.Context, d decision, begun time.Time, exit int, relayed, redactions int64, reason string) {
	if s.cfg.Audit == nil {
		return
	}
	extra := map[string]any{
		"run_id": d.runID, "op": d.op, "exit": exit, "duration_ms": time.Since(begun).Milliseconds(),
		"bytes_relayed": relayed, "redactions": redactions,
	}
	if reason != "" {
		extra["reason"] = reason
	}
	outcome := audit.OutcomeOK
	if exit != 0 {
		outcome = audit.OutcomeError
	}
	_ = s.cfg.Audit.Emit(ctx, audit.Event{Action: audit.ActionRunExited, Outcome: outcome, Extra: extra})
}

func (s *Server) emitEgressDenied(ctx context.Context, connection, host, reason string) {
	if s.cfg.Audit == nil {
		return
	}
	_ = s.cfg.Audit.Emit(ctx, audit.Event{Action: audit.ActionEgressDenied, Outcome: audit.OutcomeDenied, Extra: map[string]any{
		"provider": connection, "host": host, "reason": reason,
	}})
}

func (s *Server) emitCanaryTripped(ctx context.Context, d decision, host, where string) {
	if s.cfg.Audit == nil {
		return
	}
	_ = s.cfg.Audit.Emit(ctx, audit.Event{Action: audit.ActionCanaryTripped, Outcome: audit.OutcomeDenied, Extra: map[string]any{
		"run_id": d.runID, "connection": d.connection, "caller_kind": string(d.res.Kind), "host": host, "where": where,
	}})
}

func stringBytes(in []string) [][]byte {
	out := make([][]byte, len(in))
	for i, v := range in {
		out[i] = []byte(v)
	}
	return out
}

func (s *Server) emitLeakSuspected(ctx context.Context, d decision, files int) {
	if s.cfg.Audit == nil {
		return
	}
	_ = s.cfg.Audit.Emit(ctx, audit.Event{Action: audit.ActionContainedLeakSuspected, Outcome: audit.OutcomeDenied, Extra: map[string]any{
		"run_id": d.runID, "connection": d.connection, "caller_kind": string(d.res.Kind), "files": files,
	}})
}

func findingPaths(fs []redactor.Finding, root string) string {
	var out []string
	for i, f := range fs {
		if i == 5 {
			out = append(out, fmt.Sprintf("and %d more", len(fs)-5))
			break
		}
		rel, err := filepath.Rel(root, f.Path)
		if err != nil {
			rel = f.Path
		}
		out = append(out, rel)
	}
	return strings.Join(out, ", ")
}

func (s *Server) newRunDir() (string, error) {
	base := s.cfg.Contained.StateDir
	if base == "" {
		return "", errors.New("no state directory is configured")
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", err
	}
	return os.MkdirTemp(base, "r")
}

// feedContained applies the client's stdin, resize and signal frames to the
// child. A client that goes away ends the run.
func (s *Server) feedContained(r *bufio.Reader, child contained.Child, cancel context.CancelFunc) {
	for {
		var c Chunk
		if err := readFrame(r, &c, maxFrame); err != nil {
			cancel()
			return
		}
		switch {
		case c.Resize != nil:
			_ = child.Resize(c.Resize.Rows, c.Resize.Cols)
		case c.Signal != 0:
			_ = child.Signal(c.Signal)
		case c.EOF:
			_ = child.Stdin().Close()
		case len(c.Data) > 0:
			if _, err := child.Stdin().Write(c.Data); err != nil {
				_ = child.Stdin().Close()
			}
		}
	}
}

// approveContained decides whether the run needs an approval and obtains it.
// Agent and host callers need one unless the policy approves the exact command
// in advance; the approval is bound to argv, tier, hosts and lifetime.
func (s *Server) approveContained(ctx context.Context, kind Kind, rr *RunRequest, plan *containedPlan, d *decision, notify func(string)) *refusal {
	if !needsApproval(plan.approval, kind) {
		return nil
	}
	if s.cfg.Approve == nil {
		return &refusal{CodeRefused, exitcode.ApprovalRequired, fmt.Sprintf("tier %s needs an approval for %s callers and this daemon cannot collect one", TierContained, kind)}
	}
	req := ApprovalRequest{
		Connection: rr.Connection, Tier: TierContained, Argv: rr.Command, Hosts: plan.hosts, TTL: plan.maxRun, Caller: kind,
		Project: plan.project, Notify: notify,
		Plan: fmt.Sprintf("run %s with the real %s value in a sandbox\n  project: %s (read-write)\n  network: %s\n  lifetime: %s",
			strings.Join(rr.Command, " "), rr.Connection, plan.project, hostList(plan.hosts), plan.maxRun),
	}
	d.approvalID = "pending"
	id, err := s.cfg.Approve(ctx, req)
	if err != nil {
		return &refusal{CodeRefused, exitcode.ApprovalRequired, "approval refused: " + err.Error()}
	}
	d.approvalID = id
	return nil
}
