package control

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/harness"
	"github.com/keylatch/keylatch/internal/keyops"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
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
	maxOutput      = 8 << 20
	sessionTTL     = 15 * time.Minute
	requestTimeout = 30 * time.Second
	execTimeout    = 5 * time.Minute
)

// Config configures a Server.
type Config struct {
	Env llmcontext.Lookup
	// Binary is the keylatch executable the daemon runs for served verbs.
	Binary string
	// Keys serves key operations and the ssh-agent endpoint. Nil disables them.
	Keys *keyops.Service
	// KeyAdmin edits the key operation allowlist. Nil disables it.
	KeyAdmin *keyops.Admin
}

// Server answers control socket requests.
type Server struct {
	cfg Config
	uid uint32
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
	kind := s.classify(peer, req)

	switch req.Op {
	case OpExec:
		_ = writeFrame(conn, s.exec(ctx, kind, req))
	case OpRunSession:
		_ = writeFrame(conn, s.runSession(kind, req.Run))
	case OpGateway:
		s.gateway(conn, r)
	case OpKey:
		_ = writeFrame(conn, s.key(ctx, kind, req.Key))
	case OpKeyPolicy:
		_ = writeFrame(conn, s.keyPolicy(ctx, kind, req.KeyPolicy))
	default:
		_ = writeFrame(conn, Response{Kind: kind, Code: CodeBadRequest, Error: fmt.Sprintf("unknown operation %q", req.Op), ExitCode: exitcode.UserError})
	}
}

// classify never grants more than the caller's signals and namespaces allow:
// a signal or an outside-namespace peer can only move a caller away from human.
func (s *Server) classify(p Peer, req Request) Kind {
	if len(req.Signals) > 0 || s.validTicket(req.Ticket) {
		return KindAgent
	}
	if !p.sharesNamespaces() {
		return KindHost
	}
	return KindHuman
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

func (s *Server) exec(ctx context.Context, kind Kind, req Request) Response {
	resp := Response{Kind: kind}
	switch {
	case slices.Contains(valueVerbs, req.Verb):
		if kind.Constrained() {
			resp.Code = CodeRefused
			resp.ExitCode = exitcode.SecurityBlock
			resp.Error = fmt.Sprintf("%q returns secret values and is not available to %s callers", req.Verb, kind)
			return resp
		}
		resp.Code = CodeRunLocally
		return resp
	case !slices.Contains(servedVerbs, req.Verb):
		resp.Code = CodeBadRequest
		resp.ExitCode = exitcode.UserError
		resp.Error = fmt.Sprintf("%q is not served by the daemon", req.Verb)
		return resp
	case req.Verb == "run" && !slices.Contains(req.Args, "--dry-run"):
		resp.Code = CodeBadRequest
		resp.ExitCode = exitcode.UserError
		resp.Error = "run is served as a session request; only --dry-run is executed by the daemon"
		return resp
	}
	for _, a := range append(slices.Clone(req.Global), req.Args...) {
		if strings.ContainsRune(a, 0) {
			resp.Code = CodeBadRequest
			resp.ExitCode = exitcode.UserError
			resp.Error = "argument contains a NUL byte"
			return resp
		}
	}

	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()
	var stdout, stderr limitedBuffer
	cmd := exec.CommandContext(ctx, s.cfg.Binary, slices.Concat(req.Global, []string{req.Verb}, req.Args)...) //nolint:gosec // G204: the binary is fixed by the daemon and the verb is allowlisted
	cmd.Env = s.childEnv(kind)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	resp.OK = err == nil
	resp.Stdout, resp.Stderr = stdout.Bytes(), stderr.Bytes()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			resp.ExitCode = exitErr.ExitCode()
		} else {
			resp.Code = CodeUnavailable
			resp.ExitCode = exitcode.OperationFailed
			resp.Error = fmt.Sprintf("run %s: %v", req.Verb, err)
		}
	}
	return resp
}

// childEnv is the daemon's own environment, never the caller's. A constrained
// caller's verbs run as an agent session so every existing guard applies.
func (s *Server) childEnv(kind Kind) []string {
	env := os.Environ()
	env = append(env, LocalEnv+"=1")
	if kind.Constrained() {
		env = append(env, harness.ManualLabel+"=1")
	}
	return env
}

func (s *Server) runSession(kind Kind, rr *RunRequest) Response {
	resp := Response{Kind: kind, Code: CodeBadRequest, ExitCode: exitcode.UserError}
	if rr == nil || rr.Connection == "" || len(rr.Command) == 0 {
		resp.Error = "a connection and a command are required"
		return resp
	}

	tier := rr.Tier
	if tier == "" {
		tier = TierGateway
	}
	switch tier {
	case TierGateway:
	case TierRaw:
		resp.Code, resp.ExitCode = CodeRefused, exitcode.SecurityBlock
		resp.Error = "tier D6 injects an uncontained secret and is never served over the socket"
		return resp
	default:
		resp.Code, resp.ExitCode = CodeUnavailable, exitcode.RuntimeNotAvailable
		resp.Error = fmt.Sprintf("tier %s is not available; supported tier: %s", tier, TierGateway)
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

	key, err := os.ReadFile(paths.GatewaySigningKey(s.cfg.Env))
	if err != nil {
		resp.Code, resp.ExitCode = CodeUnavailable, exitcode.OperationFailed
		resp.Error = "gateway signing key is not available to the daemon"
		return resp
	}
	defer clear(key)
	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "thin_client:" + string(kind),
		Capabilities: []string{tmpl.Provider + ".*"},
		TTL:          sessionTTL,
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
func (s *Server) gateway(conn *net.UnixConn, r *bufio.Reader) {
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
		_, _ = io.Copy(up, r)
		if tc, ok := up.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, up)
		_ = conn.CloseWrite()
		done <- struct{}{}
	}()
	<-done
	<-done
}

// limitedBuffer keeps the first maxOutput bytes and discards the rest.
type limitedBuffer struct{ buf bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := maxOutput - b.buf.Len(); room > 0 {
		b.buf.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

func (b *limitedBuffer) Bytes() []byte { return b.buf.Bytes() }
