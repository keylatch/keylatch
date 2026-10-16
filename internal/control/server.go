package control

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/adapter"
	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend/childstore"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/keyops"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/mintsession"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/placeholder"
	"github.com/keylatch/keylatch/internal/policy/enforce"
	"github.com/keylatch/keylatch/internal/policy/mint"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/runtime"
)

// Response codes.
const (
	CodeRefused     = "refused"
	CodeRunLocally  = "run_locally"
	CodeBadRequest  = "bad_request"
	CodeUnavailable = "unavailable"
	CodeNotFound    = "not_found"
	// CodeInvalidSignature answers a verify whose signature does not match.
	CodeInvalidSignature = "invalid_signature"
)

// servedVerbs are the read-only verbs the daemon executes for any caller.
var servedVerbs = []string{"status", "list", "doctor", "describe", "explain", "call", "run"}

// valueVerbs return secret values. The daemon never serves them to agent or
// host callers; for a human it tells the client to run them locally.
var valueVerbs = []string{"get", "export", "backup", "mint"}

// IsServedVerb reports whether the thin client sends verb to the daemon.
func IsServedVerb(verb string) bool {
	return slices.Contains(servedVerbs, verb) || slices.Contains(valueVerbs, verb)
}

const (
	sessionTTL     = token.DefaultTTL
	sessionMaxUses = 1000
	requestTimeout = 30 * time.Second
	execTimeout    = 5 * time.Minute
)

// MintFunc opens the credential behind a template whose fields Keylatch mints
// at use time, after checking the request against the connection's policy.
type MintFunc func(ctx context.Context, kind Kind, rr *RunRequest) (placeholder.Credential, error)

// Config configures a Server.
type Config struct {
	Env llmcontext.Lookup
	// Binary is the keylatch executable the daemon runs for served verbs.
	Binary string
	// Placeholders serves tier D3. Without it D3 is unavailable.
	Placeholders *placeholder.Manager
	// Mint opens the credential behind a template whose fields Keylatch mints
	// at use time. Without it such templates cannot be served.
	Mint MintFunc
	// Keys serves key operations and the ssh-agent endpoint. Nil disables them.
	Keys *keyops.Service
	// KeyAdmin edits the key operation allowlist. Nil disables it.
	KeyAdmin *keyops.Admin
	// Audit receives one value-free event per decision. Nil records nothing.
	Audit audit.Emitter
	// Callers classifies socket peers. Nil walks the real process tree.
	Callers *callerkind.Classifier
	// SigningKey returns the gateway signing key session tokens are minted
	// with. Nil means the gateway cannot be served.
	SigningKey func() ([]byte, error)
	// Contained serves tier D5. Nil refuses it.
	Contained *ContainedConfig
	// Adapters serves tier D4. Without it D4 is unavailable.
	Adapters *adapter.Manager
	// Custom returns the template of a connection that declares its own
	// bindings. Without it only provider templates are served at D3 and D5.
	Custom func(ctx context.Context, name string) (registry.ConnectionTemplate, error)
	// Decide is the policy engine. Tier D5 is refused without it.
	Decide func(ctx context.Context, req enforce.Request) enforce.Decision
	// Approve obtains approval for a run that needs one. Without it such a
	// run is refused.
	Approve Approver
	// ChildEnv is added to the environment of the verbs the daemon runs.
	ChildEnv []string
	// ChildStore, when set, answers the store reads of the verbs the daemon
	// runs, over a descriptor the verb inherits. Without it they use their own
	// configured backend.
	ChildStore childstore.Source
	// Gate is asked before the daemon acts on policy, credentials or keys for a
	// caller. An error refuses the request.
	Gate func(ctx context.Context, res callerkind.Result) error
	// Ticket verifies a session ticket. Nil verifies it with the local ticket
	// key.
	Ticket func(raw string, p Peer) bool
	// Extension serves operations the control protocol does not define.
	Extension Extension
}

// Extension serves operations the control protocol does not define.
type Extension interface {
	// Handle answers the request in raw. It reports false for an operation it
	// does not serve, and the server then refuses it.
	Handle(ctx context.Context, conn *net.UnixConn, p Peer, res callerkind.Result, raw []byte) bool
}

// Server answers control socket requests.
type Server struct {
	cfg  Config
	uid  uint32
	runs runTable
}

// NewServer returns a Server that accepts peers running as the daemon's user.
func NewServer(cfg Config) *Server {
	if cfg.Env == nil {
		cfg.Env = llmcontext.DefaultLookup
	}
	return &Server{cfg: cfg, uid: uint32(os.Getuid())} //nolint:gosec // G115: uid is non-negative
}

// Listen binds the control socket at path, creating its owner-only directory
// and replacing a stale socket left by a dead daemon.
func Listen(path string) (*net.UnixListener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("control: create socket directory: %w", err)
	}
	if err := paths.AssertSafeModes(dir); err != nil {
		return nil, fmt.Errorf("control: socket directory: %w", err)
	}
	if _, err := os.Lstat(path); err == nil {
		if conn, derr := net.DialTimeout("unix", path, time.Second); derr == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("control: a daemon is already listening on %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("control: remove stale socket: %w", err)
		}
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("control: listen: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("control: restrict socket: %w", err)
	}
	return ln, nil
}

// Serve accepts connections until ctx is done.
func (s *Server) Serve(ctx context.Context, ln *net.UnixListener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { _ = conn.Close() }()
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) handle(ctx context.Context, conn *net.UnixConn) {
	peer, err := peerOf(conn)
	if err != nil || peer.UID != s.uid {
		return
	}
	s.ServeConn(ctx, conn, peer)
}

// ServeConn answers the request on conn from a peer the caller has already
// identified and admitted.
func (s *Server) ServeConn(ctx context.Context, conn *net.UnixConn, peer Peer) {
	r := bufio.NewReader(conn)
	var req Request
	_ = conn.SetReadDeadline(time.Now().Add(requestTimeout))
	raw, err := readLine(r, maxFrame)
	if err == nil {
		err = decodeFrame(raw, &req)
	}
	if err != nil {
		_ = writeFrame(conn, Response{Code: CodeBadRequest, Error: err.Error(), ExitCode: exitcode.UserError})
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	if peer.Verify != nil {
		if err := peer.Verify(); err != nil {
			_ = writeFrame(conn, Response{Code: CodeRefused, ExitCode: exitcode.SecurityBlock, Error: err.Error()})
			return
		}
	}
	res := s.classify(peer, req)
	kind := res.Kind

	if s.cfg.Gate != nil && gated(req) {
		if err := s.cfg.Gate(ctx, res); err != nil {
			_ = s.record(ctx, decision{op: string(req.Op), verb: req.Verb, res: res, reason: err.Error()}, audit.OutcomeDenied)
			_ = writeFrame(conn, Response{Kind: kind, Code: CodeRefused, ExitCode: exitcode.SecurityBlock, Error: err.Error()})
			return
		}
	}

	switch req.Op {
	case OpExec:
		s.exec(ctx, conn, r, res, req)
	case OpRunSession:
		_ = writeFrame(conn, s.decideRun(ctx, res, req.Run))
	case OpContained:
		s.containedRun(ctx, conn, r, res, req)
	case OpRunExit:
		_ = writeFrame(conn, s.runExited(ctx, req))
	case OpGateway:
		s.gateway(conn, r, s.runs.get(req.RunID))
	case OpProxy:
		s.proxy(conn, r, req.Proxy, s.runs.get(req.RunID))
	case OpEndSession:
		_ = writeFrame(conn, s.endSession(kind, req.Proxy))
	case OpCredential:
		_ = writeFrame(conn, s.credential(kind, req.Proxy, req.Credential))
	case OpKey:
		_ = writeFrame(conn, s.key(ctx, kind, req.Key))
	case OpKeyPolicy:
		_ = writeFrame(conn, s.keyPolicy(ctx, kind, req.KeyPolicy))
	default:
		if s.cfg.Extension != nil && s.cfg.Extension.Handle(ctx, conn, peer, res, raw) {
			return
		}
		resp := Response{Kind: kind, Code: CodeBadRequest, Error: fmt.Sprintf("unknown operation %q", req.Op), ExitCode: exitcode.UserError}
		if err := s.record(ctx, decision{op: string(req.Op), res: res, reason: "unknown operation"}, audit.OutcomeDenied); err != nil {
			resp = auditRefusal(resp, err)
		}
		_ = writeFrame(conn, resp)
	}
}

// classify never grants more than the evidence allows: signals the client
// sends, a ticket, the peer's ancestry and its namespaces can only move a
// caller away from human.
func (s *Server) classify(p Peer, req Request) callerkind.Result {
	return s.cfg.Callers.Peer(callerkind.Evidence{
		PID:              p.PID,
		Cgroup:           p.Cgroup,
		SharesNamespaces: callerkind.SharesNamespaces(p.PID),
		Signals:          req.Signals,
		TicketValid:      s.validTicket(req.Ticket, p),
	})
}

// gated reports whether a request acts on policy, credentials or keys, so a
// broken policy must stop it. Read-only diagnostics stay available.
func gated(req Request) bool {
	switch req.Op {
	case OpExec:
		return slices.Contains(valueVerbs, req.Verb) || req.Verb == "call" || req.Verb == "run"
	case OpRunSession, OpContained, OpGateway, OpProxy, OpCredential, OpKey, OpKeyPolicy:
		return true
	}
	return false
}

func (s *Server) validTicket(raw string, p Peer) bool {
	if raw == "" {
		return false
	}
	if s.cfg.Ticket != nil {
		return s.cfg.Ticket(raw, p)
	}
	key, err := os.ReadFile(paths.SessionTicketKey(s.cfg.Env))
	if err != nil {
		return false
	}
	defer clear(key)
	_, err = llmcontext.VerifyTicket(raw, key)
	return err == nil
}

// runSession answers a session request. When it issues a gateway token it
// sets *revoke to the function that revokes it.
func (s *Server) runSession(ctx context.Context, kind Kind, rr *RunRequest, revoke *func()) Response {
	resp := Response{Kind: kind, Code: CodeBadRequest, ExitCode: exitcode.UserError}
	if rr == nil || rr.Connection == "" || len(rr.Command) == 0 {
		resp.Error = "a connection and a command are required"
		return resp
	}

	tier := rr.Tier
	if tier == "" {
		tier = s.preferredTier(rr)
	}
	if tier == TierGateway || tier == TierPlaceholder || tier == TierAdapter {
		dec, f := s.gateTier(ctx, kind, rr, tier, false)
		if f == nil && needsApproval(dec.Approval, kind) && dec.Approval != "" {
			f = s.approveSession(ctx, kind, rr, tier, dec)
		}
		if f != nil {
			resp.Code, resp.ExitCode, resp.Error = f.code, f.exit, f.msg
			return resp
		}
	}
	switch tier {
	case TierGateway:
	case TierPlaceholder:
		return s.placeholderSession(ctx, kind, rr)
	case TierAdapter:
		return s.adapterSession(ctx, kind, rr)
	case TierContained:
		resp.Code, resp.ExitCode = CodeBadRequest, exitcode.UserError
		resp.Error = "tier D5 runs in the daemon's sandbox and is requested with a contained run, not a session"
		return resp
	case TierRaw:
		resp.Code, resp.ExitCode = CodeRefused, exitcode.SecurityBlock
		resp.Error = "tier D6 injects an uncontained secret and is never served over the socket"
		return resp
	default:
		resp.Code, resp.ExitCode = CodeUnavailable, exitcode.RuntimeNotAvailable
		resp.Error = fmt.Sprintf("tier %s is not available; supported tiers: %s, %s, %s", tier, TierGateway, TierPlaceholder, TierAdapter)
		return resp
	}

	mode := runtime.RuntimeMode(rr.Runtime)
	if mode == "" {
		mode = runtime.RuntimeGatewayTyped
	}
	if mode != runtime.RuntimeGatewayTyped && mode != runtime.RuntimeGatewaySDK {
		resp.Error = fmt.Sprintf("tier %s supports runtimes %s and %s, not %s", tier, runtime.RuntimeGatewayTyped, runtime.RuntimeGatewaySDK, mode)
		return resp
	}

	tmpl, err := registry.Get(rr.Connection)
	if err != nil {
		resp.Code, resp.ExitCode = CodeNotFound, exitcode.Missing
		resp.Error = fmt.Sprintf("unknown connection %q", rr.Connection)
		return resp
	}

	addr, err := s.gatewayAddr()
	if err == nil {
		err = probe(addr)
	}
	if err != nil {
		resp.Code, resp.ExitCode = CodeUnavailable, exitcode.OperationFailed
		resp.Error = "gateway is not running: start it with 'keylatch gateway up'"
		return resp
	}

	var key []byte
	if s.cfg.SigningKey != nil {
		key, err = s.cfg.SigningKey()
	} else {
		err = errors.New("no signing key source")
	}
	if err != nil {
		resp.Code, resp.ExitCode = CodeUnavailable, exitcode.OperationFailed
		resp.Error = "gateway signing key is not available to the daemon"
		return resp
	}
	defer clear(key)
	storePath := paths.GatewayTokens(s.cfg.Env)
	jwtStr, tok, err := token.Mint(token.TokenSpec{
		Actor:        "thin_client:" + string(kind),
		Capabilities: tmpl.GatewayCapabilities(),
		TTL:          sessionTTL,
		MaxUses:      sessionMaxUses,
		Caller:       kind,
		LLMSession:   kind.Constrained(),
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		resp.Code, resp.ExitCode = CodeUnavailable, exitcode.OperationFailed
		resp.Error = "could not issue a session token"
		return resp
	}
	*revoke = func() { s.revokeToken(tok.ID, storePath) }

	return Response{OK: true, Kind: kind, Session: &Session{
		Tier:       tier,
		Runtime:    string(mode),
		Env:        runner.GatewaySessionEnv(mode, tmpl, "http://"+runner.GatewayAddrPlaceholder, jwtStr),
		TTLSeconds: int(sessionTTL.Seconds()),
	}}
}

// revokeToken revokes an issued session token. The signing key is read again
// because the daemon does not keep it in memory between requests.
func (s *Server) revokeToken(id, storePath string) {
	if s.cfg.SigningKey == nil {
		return
	}
	key, err := s.cfg.SigningKey()
	if err != nil {
		slog.Warn("session token not revoked: signing key unavailable", "error", err)
		return
	}
	defer clear(key)
	if err := token.Revoke(id, storePath, key); err != nil {
		slog.Warn("session token not revoked", "error", err)
	}
}

// template returns the provider template of a connection, or the one a custom
// connection builds from its own bindings.
func (s *Server) template(ctx context.Context, name string) (registry.ConnectionTemplate, error) {
	tmpl, err := registry.Get(name)
	if err != nil && s.cfg.Custom != nil {
		return s.cfg.Custom(ctx, name)
	}
	return tmpl, err
}

// preferredTier is the strongest tier the daemon can serve for the request:
// placeholder substitution when the template binds its credentials to hosts,
// the gateway otherwise.
func (s *Server) preferredTier(rr *RunRequest) Tier {
	if s.cfg.Placeholders == nil || rr.Runtime != "" {
		return TierGateway
	}
	tmpl, err := s.template(context.Background(), rr.Connection)
	if err != nil {
		return TierGateway
	}
	if b, ok := tmpl.Binding(); ok && len(b.Slots) > 0 {
		return TierPlaceholder
	}
	return TierGateway
}

func (s *Server) placeholderSession(ctx context.Context, kind Kind, rr *RunRequest) Response {
	resp := Response{Kind: kind, Code: CodeBadRequest, ExitCode: exitcode.UserError}
	if s.cfg.Placeholders == nil {
		resp.Code, resp.ExitCode = CodeUnavailable, exitcode.RuntimeNotAvailable
		resp.Error = "tier D3 is not available: the daemon has no credential store or audit log for placeholder substitution"
		return resp
	}
	if rr.Runtime != "" && rr.Runtime != placeholderRuntime {
		resp.Error = fmt.Sprintf("tier D3 does not take the %s runtime", rr.Runtime)
		return resp
	}
	tmpl, err := s.template(ctx, rr.Connection)
	if err != nil {
		resp.Code, resp.ExitCode = CodeNotFound, exitcode.Missing
		resp.Error = fmt.Sprintf("unknown connection %q", rr.Connection)
		return resp
	}
	var cred placeholder.Credential
	if len(tmpl.MintedFields) > 0 {
		if s.cfg.Mint == nil {
			resp.Code, resp.ExitCode = CodeUnavailable, exitcode.RuntimeNotAvailable
			resp.Error = fmt.Sprintf("connection %q mints its credential and the daemon has no minting configured", rr.Connection)
			return resp
		}
		cred, err = s.cfg.Mint(ctx, kind, rr)
		if err != nil {
			return mintRefusal(resp, err)
		}
	}
	sess, err := s.cfg.Placeholders.Open(placeholder.OpenRequest{Template: tmpl, UpstreamProxy: rr.UpstreamProxy, Credential: cred})
	if err != nil {
		if cred != nil {
			cred.Close()
		}
		if errors.Is(err, placeholder.ErrNoBinding) {
			resp.Error = fmt.Sprintf("connection %q declares no host bindings, so tier D3 cannot serve it", rr.Connection)
			return resp
		}
		resp.Code, resp.ExitCode = CodeUnavailable, exitcode.OperationFailed
		resp.Error = fmt.Sprintf("could not open a placeholder session: %v", err)
		return resp
	}
	env := runner.PlaceholderSessionEnv(tmpl, sess.Placeholders(), "http://"+runner.GatewayAddrPlaceholder)
	env.Set = append(env.Set, runner.GitCredentialEnv(tmpl, sess.ID())...)
	env.Set = append(env.Set, runner.DockerCredentialEnv(tmpl, sess.ID())...)
	for _, name := range slices.Sorted(maps.Keys(sess.Canaries())) {
		env.Set = append(env.Set, runner.EnvAssign{Name: name, Value: sess.Canaries()[name]})
	}
	return Response{OK: true, Kind: kind, Session: &Session{
		Tier:       TierPlaceholder,
		Runtime:    placeholderRuntime,
		Env:        env,
		TTLSeconds: int(sess.TTL().Seconds()),
		ProxyID:    sess.ID(),
		CAPEM:      string(sess.CAPEM()),
		CAVars:     runner.CABundleVars,
	}}
}

// mintRefusal maps a failure to open a minted credential to a response. The
// messages name policy and request problems only, never key material.
func mintRefusal(resp Response, err error) Response {
	switch {
	case errors.Is(err, mint.ErrDenied), errors.Is(err, mint.ErrInvalidPolicy):
		resp.Code, resp.ExitCode = CodeRefused, exitcode.PolicyDeny
	case errors.Is(err, mintsession.ErrUsage):
		resp.Code, resp.ExitCode = CodeBadRequest, exitcode.UserError
	default:
		resp.Code, resp.ExitCode = CodeUnavailable, exitcode.OperationFailed
	}
	resp.Error = err.Error()
	return resp
}

// isCredentialHelper reports whether the adapter kind is served by a
// credential helper: the git helper and the Docker credential store.
func isCredentialHelper(kind registry.AdapterKind) bool {
	return kind == registry.AdapterGitCredential || kind == registry.AdapterDockerCredential
}

// credential answers a credential helper (git, Docker) with the placeholder
// bound to the session, for hosts the template's adapter names and nothing
// else. It never has the real value to give.
func (s *Server) credential(kind Kind, id string, req *CredentialRequest) Response {
	resp := Response{OK: true, Kind: kind}
	if s.cfg.Placeholders == nil || req == nil || req.Protocol != "https" {
		return resp
	}
	sess, ok := s.cfg.Placeholders.Get(id)
	if !ok || sess.Suspended() {
		return resp
	}
	tmpl, err := registry.Get(sess.Connection())
	if err != nil || !isCredentialHelper(tmpl.Adapter.Kind) {
		return resp
	}
	host := strings.ToLower(req.Host)
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	if !slices.ContainsFunc(tmpl.Adapter.Hosts, func(h string) bool { return registry.MatchAuthority(h, host) }) {
		return resp
	}
	if pw, ok := sess.Placeholders()[tmpl.Adapter.Field]; ok {
		resp.Credential = &Credential{Username: tmpl.Adapter.Username, Password: pw}
	}
	return resp
}

// placeholderRuntime is the runtime name reported for tier D3.
const placeholderRuntime = "placeholder"

type bufferedConn struct {
	net.Conn
	r   *bufio.Reader
	run *runState
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.run.relayed(n)
	return n, err
}

func (c *bufferedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.run.relayed(n)
	return n, err
}

// proxy turns the connection into a client connection of a placeholder
// session's proxy and serves it until it closes.
func (s *Server) proxy(conn *net.UnixConn, r *bufio.Reader, id string, run *runState) {
	var sess *placeholder.Session
	if s.cfg.Placeholders != nil {
		sess, _ = s.cfg.Placeholders.Get(id)
	}
	var ad *adapter.Session
	if sess == nil && s.cfg.Adapters != nil {
		ad, _ = s.cfg.Adapters.Get(id)
	}
	if sess == nil && ad == nil {
		_ = writeFrame(conn, Response{Code: CodeNotFound, ExitCode: exitcode.Missing, Error: "no such placeholder session"})
		return
	}
	if err := writeFrame(conn, Response{OK: true}); err != nil {
		return
	}
	bc := &bufferedConn{Conn: conn, r: r, run: run}
	if ad != nil {
		ad.Serve(bc)
		return
	}
	sess.Serve(bc)
}

func (s *Server) endSession(kind Kind, id string) Response {
	if s.cfg.Placeholders != nil {
		if sess, ok := s.cfg.Placeholders.Get(id); ok {
			sess.Close("run_ended")
		}
	}
	if s.cfg.Adapters != nil {
		if sess, ok := s.cfg.Adapters.Get(id); ok {
			sess.Close("run_ended")
		}
	}
	return Response{OK: true, Kind: kind}
}

func (s *Server) gatewayAddr() (string, error) {
	addr := s.cfg.Env("KEYLATCH_GATEWAY_ADDR")
	if addr == "" {
		return "127.0.0.1:7878", nil
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return "", fmt.Errorf("KEYLATCH_GATEWAY_ADDR: %w", err)
	}
	return addr, nil
}

func probe(addr string) error {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	return c.Close()
}

// gateway pipes the connection to the gateway. The gateway authenticates each
// request itself, so the stream grants nothing without a session token.
func (s *Server) gateway(conn *net.UnixConn, r *bufio.Reader, run *runState) {
	addr, err := s.gatewayAddr()
	var up net.Conn
	if err == nil {
		up, err = net.DialTimeout("tcp", addr, 2*time.Second)
	}
	if err != nil {
		_ = writeFrame(conn, Response{Code: CodeUnavailable, ExitCode: exitcode.OperationFailed, Error: "gateway is not running"})
		return
	}
	defer func() { _ = up.Close() }()
	if err := writeFrame(conn, Response{OK: true}); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(up, r)
		run.relayed(int(n))
		if tc, ok := up.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(conn, up)
		run.relayed(int(n))
		_ = conn.CloseWrite()
		done <- struct{}{}
	}()
	<-done
	<-done
}
