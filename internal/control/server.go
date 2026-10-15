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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/keyops"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/mintsession"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/placeholder"
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
	r := bufio.NewReader(conn)
	var req Request
	_ = conn.SetReadDeadline(time.Now().Add(requestTimeout))
	if err := readFrame(r, &req, maxFrame); err != nil {
		_ = writeFrame(conn, Response{Code: CodeBadRequest, Error: err.Error(), ExitCode: exitcode.UserError})
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	res := s.classify(peer, req)
	kind := res.Kind

	switch req.Op {
	case OpExec:
		s.exec(ctx, conn, r, res, req)
	case OpRunSession:
		_ = writeFrame(conn, s.decideRun(ctx, res, req.Run))
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
		SharesNamespaces: callerkind.SharesNamespaces(p.PID),
		Signals:          req.Signals,
		TicketValid:      s.validTicket(req.Ticket),
	})
}

func (s *Server) validTicket(raw string) bool {
	if raw == "" {
		return false
	}
	key, err := os.ReadFile(paths.SessionTicketKey(s.cfg.Env))
	if err != nil {
		return false
	}
	defer clear(key)
	_, err = llmcontext.VerifyTicket(raw, key)
	return err == nil
}

func (s *Server) runSession(ctx context.Context, kind Kind, rr *RunRequest) Response {
	resp := Response{Kind: kind, Code: CodeBadRequest, ExitCode: exitcode.UserError}
	if rr == nil || rr.Connection == "" || len(rr.Command) == 0 {
		resp.Error = "a connection and a command are required"
		return resp
	}

	tier := rr.Tier
	if tier == "" {
		tier = s.preferredTier(rr)
	}
	switch tier {
	case TierGateway:
	case TierPlaceholder:
		return s.placeholderSession(ctx, kind, rr)
	case TierRaw:
		resp.Code, resp.ExitCode = CodeRefused, exitcode.SecurityBlock
		resp.Error = "tier D6 injects an uncontained secret and is never served over the socket"
		return resp
	default:
		resp.Code, resp.ExitCode = CodeUnavailable, exitcode.RuntimeNotAvailable
		resp.Error = fmt.Sprintf("tier %s is not available; supported tiers: %s, %s", tier, TierGateway, TierPlaceholder)
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
	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "thin_client:" + string(kind),
		Capabilities: tmpl.GatewayCapabilities(),
		TTL:          sessionTTL,
		MaxUses:      sessionMaxUses,
		Kind:         string(kind),
		LLMSession:   kind.Constrained(),
		SigningKey:   key,
		StorePath:    paths.GatewayTokens(s.cfg.Env),
	})
	if err != nil {
		resp.Code, resp.ExitCode = CodeUnavailable, exitcode.OperationFailed
		resp.Error = "could not issue a session token"
		return resp
	}

	return Response{OK: true, Kind: kind, Session: &Session{
		Tier:       tier,
		Runtime:    string(mode),
		Env:        runner.GatewaySessionEnv(mode, tmpl, "http://"+runner.GatewayAddrPlaceholder, jwtStr),
		TTLSeconds: int(sessionTTL.Seconds()),
	}}
}

// preferredTier is the strongest tier the daemon can serve for the request:
// placeholder substitution when the template binds its credentials to hosts,
// the gateway otherwise.
func (s *Server) preferredTier(rr *RunRequest) Tier {
	if s.cfg.Placeholders == nil || rr.Runtime != "" {
		return TierGateway
	}
	tmpl, err := registry.Get(rr.Connection)
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
	tmpl, err := registry.Get(rr.Connection)
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

// credential answers a git credential helper with the placeholder bound to the
// session, for hosts the template's git adapter names and nothing else.
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
	if err != nil || tmpl.Adapter.Kind != registry.AdapterGitCredential {
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
	if sess == nil {
		_ = writeFrame(conn, Response{Code: CodeNotFound, ExitCode: exitcode.Missing, Error: "no such placeholder session"})
		return
	}
	if err := writeFrame(conn, Response{OK: true}); err != nil {
		return
	}
	sess.Serve(&bufferedConn{Conn: conn, r: r, run: run})
}

func (s *Server) endSession(kind Kind, id string) Response {
	if s.cfg.Placeholders != nil {
		if sess, ok := s.cfg.Placeholders.Get(id); ok {
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
