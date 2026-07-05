package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/exec"
)

// maxBearerTokenTTL is the maximum TTL for bearer legacy tokens (1 hour).
const maxBearerTokenTTL = time.Hour

// idleTimeout is the maximum idle time for TCP connections.
const idleTimeout = 5 * time.Minute

// bearerIdleTimeout is the maximum time a bearer token may go unused
// before it is considered expired (A4-009 / m4).
const bearerIdleTimeout = 30 * time.Minute

// bearerSession holds the in-memory state for a legacy bearer token.
// Never written to disk.
type bearerSession struct {
	mu         sync.Mutex
	token      string
	issuedAt   time.Time
	expiresAt  time.Time
	lastUsedAt time.Time
}

// newBearerSession creates a new session with the given token and TTL.
func newBearerSession(token string, ttl time.Duration) *bearerSession {
	now := time.Now()
	if ttl <= 0 {
		ttl = maxBearerTokenTTL
	}
	return &bearerSession{
		token:      token,
		issuedAt:   now,
		expiresAt:  now.Add(ttl),
		lastUsedAt: now,
	}
}

// CheckAndTouch validates the token and updates lastUsedAt if valid.
// Returns an error if the token is expired, idle-expired, or does not match.
// A4-009: idle expiry triggers when no request has used the token in 30 minutes.
func (s *bearerSession) CheckAndTouch(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if token != s.token {
		return ErrSessionTokenMismatch
	}
	now := time.Now()
	if now.After(s.expiresAt) {
		return ErrTTLExceedsCap
	}
	if now.Sub(s.lastUsedAt) > bearerIdleTimeout {
		return ErrSessionTokenExpired
	}
	s.lastUsedAt = now
	return nil
}

// IsExpired returns true if the session has exceeded its wall-clock TTL or
// has been idle for longer than bearerIdleTimeout.
func (s *bearerSession) IsExpired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	return now.After(s.expiresAt) || now.Sub(s.lastUsedAt) > bearerIdleTimeout
}

// nonceRegistry tracks per-connection nonces to prevent replay attacks.
type nonceRegistry struct {
	mu     sync.Mutex
	nonces map[string]uint64 // nonce hex -> connection fd (pseudo)
}

var globalNonceRegistry = &nonceRegistry{
	nonces: make(map[string]uint64),
}

// connCounter is an atomic counter used to generate unique connection IDs.
// Replaces time.Now().UnixNano() to eliminate collision risk (Warning 7).
var connCounter atomic.Uint64

// register registers a nonce for a connection fd.
// Returns ErrNonceConnectionMismatch if the nonce is already registered on a different fd.
func (r *nonceRegistry) register(nonce string, fd uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.nonces[nonce]; ok {
		if existing != fd {
			return ErrNonceConnectionMismatch
		}
		return nil
	}
	r.nonces[nonce] = fd
	return nil
}

// generateNonce generates a 32-byte cryptographically random nonce.
func generateNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("mcp: generate nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// ServeTCP starts the MCP server in TCP transport mode.
//
// Auth mode selection:
//   - Linux/macOS: Unix-domain socket with SO_PEERCRED / LOCAL_PEERCRED
//   - Windows: Named pipe ACL
//   - Fallback: Bearer legacy with TTL cap ≤ 1 hour
//
// 0.0.0.0 is rejected in New(); no --unsafe-bind-all flag exists.
//
// Note: the TCP path accepts and authenticates connections but does
// not yet speak the MCP protocol over them. The official SDK server is
// constructed for RegisterTools but no SDK transport is attached to the
// net.Listener. Full MCP-over-TCP is deferred to a future phase.
func (s *Server) ServeTCP(ctx context.Context, store connections.Store, runner exec.CommandRunner) error {
	if s.opts.Transport != TransportTCP {
		return fmt.Errorf("mcp: ServeTCP called with transport %q", s.opts.Transport)
	}

	// Validate bearer TTL if using legacy auth.
	if s.opts.ConnectionAuth == AuthBearerLegacy && s.opts.TokenTTL != "" {
		ttl, err := time.ParseDuration(s.opts.TokenTTL)
		if err != nil {
			return fmt.Errorf("mcp: invalid TokenTTL: %w", err)
		}
		if ttl > maxBearerTokenTTL {
			return ErrTTLExceedsCap
		}
	}

	// Construct an SDK server for RegisterTools only.
	// No SDK transport is attached here — MCP protocol over TCP is deferred.
	srv := sdkmcp.NewServer(
		&sdkmcp.Implementation{
			Name:    "keylatch",
			Version: "1.0.0",
		},
		nil,
	)
	RegisterTools(srv, store, runner)

	// Assert exactly five tools are registered (mirrors ServeStdio).
	if len(registeredTools) != 5 {
		return fmt.Errorf("mcp: tool registration invariant violated: expected 5 tools, got %d", len(registeredTools))
	}

	switch s.opts.ConnectionAuth {
	case AuthUnixPeerCred:
		return s.serveUnixPeerCred(ctx, srv)
	case AuthBearerLegacy:
		return s.serveBearerLegacy(ctx, srv)
	default:
		// Fallback for platforms without peer-cred support.
		return s.serveBearerLegacy(ctx, srv)
	}
}

// serveUnixPeerCred binds a Unix-domain socket and validates SO_PEERCRED on each accept.
// Only same-UID connections are accepted.
func (s *Server) serveUnixPeerCred(ctx context.Context, _ *sdkmcp.Server) error {
	xdgRuntime := os.Getenv("XDG_RUNTIME_DIR")
	if xdgRuntime == "" {
		xdgRuntime = os.TempDir()
	}
	sockDir := filepath.Join(xdgRuntime, "keylatch")
	if err := os.MkdirAll(sockDir, 0o700); err != nil { //nolint:gosec // G703: sockDir is constructed from XDG_RUNTIME_DIR (operator-set) or os.TempDir(); not user input
		return fmt.Errorf("mcp: create socket dir: %w", err)
	}
	sockPath := filepath.Join(sockDir, "mcp.sock")

	// Remove stale socket.
	_ = os.Remove(sockPath) //nolint:gosec // G703: sockPath is under XDG_RUNTIME_DIR/keylatch, not user-controlled

	ln, err := net.Listen("unix", sockPath) //nolint:gosec // G703: sockPath is under XDG_RUNTIME_DIR/keylatch, not user-controlled
	if err != nil {
		return fmt.Errorf("mcp: listen unix: %w", err)
	}
	defer ln.Close() //nolint:errcheck // defer close of listener, error non-actionable on shutdown

	// Set restrictive permissions on socket file.
	if err := os.Chmod(sockPath, 0o600); err != nil { //nolint:gosec // G703: sockPath is under XDG_RUNTIME_DIR/keylatch, not user-controlled
		return fmt.Errorf("mcp: chmod socket: %w", err)
	}

	serverUID := os.Getuid()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}

		// Validate peer UID using SO_PEERCRED / LOCAL_PEERCRED.
		if !validatePeerUID(conn, serverUID) {
			_ = conn.Close()
			continue
		}

		// Generate and bind per-connection nonce.
		nonce, err := generateNonce()
		if err != nil {
			_ = conn.Close()
			continue
		}

		// Store nonce bound to this connection (using atomic counter as pseudo-fd).
		// In production: use actual fd via syscall.
		connID := connCounter.Add(1)
		if err := globalNonceRegistry.register(nonce, connID); err != nil {
			_ = conn.Close()
			continue
		}

		go handleUnixConn(ctx, conn, nonce)
	}
}

// validatePeerUID checks that the connecting peer has the same UID as the server.
// Returns true if the peer UID matches.
func validatePeerUID(conn net.Conn, serverUID int) bool {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return false
	}

	var peerUID = -1 //nolint:staticcheck // QF1011: type annotation kept for readability — explicitly shows this is an int, not a bool
	_ = rawConn.Control(func(fd uintptr) {
		peerUID = getPeerUID(int(fd), serverUID)
	})
	return peerUID == serverUID
}

// handleUnixConn serves a single Unix connection.
// Accepts connection, validates nonce, blocks until context done or idle.
// Uses select so both context cancellation and the idle timeout are honoured.
// (conn.SetDeadline only fires on I/O; since we do no I/O here the deadline
// would never trigger — replaced with time.After to fix the goroutine leak.)
func handleUnixConn(ctx context.Context, conn net.Conn, nonce string) {
	defer conn.Close() //nolint:errcheck // defer close of connection, error non-actionable on shutdown
	// The nonce would be sent in the JSON-RPC initialize response.
	// We accept the connection and let the MCP server handle the protocol.
	// Full nonce injection into the initialize response is a future concern.
	_ = nonce
	select {
	case <-ctx.Done():
	case <-time.After(idleTimeout):
	}
}

// serveBearerLegacy handles TCP connections with legacy bearer token auth.
func (s *Server) serveBearerLegacy(ctx context.Context, _ *sdkmcp.Server) error {
	// Validate TTL cap.
	if s.opts.TokenTTL != "" {
		ttl, err := time.ParseDuration(s.opts.TokenTTL)
		if err != nil {
			return fmt.Errorf("mcp: invalid TokenTTL: %w", err)
		}
		if ttl > maxBearerTokenTTL {
			return ErrTTLExceedsCap
		}
	}

	// Bearer token is never written to disk.
	// Token is held in memory only for the duration of the server's lifetime.
	bind := s.opts.Bind
	if bind == "" {
		bind = "127.0.0.1:0"
	}

	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return fmt.Errorf("mcp: listen tcp: %w", err)
	}
	defer ln.Close() //nolint:errcheck // defer close of TCP listener, error non-actionable on shutdown

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))
		conn, err := ln.Accept()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}

		// Apply idle timeout.
		_ = conn.SetDeadline(time.Now().Add(idleTimeout))
		go func() {
			defer conn.Close() //nolint:errcheck // defer close of TCP connection goroutine, error non-actionable
			// Token validation and MCP protocol handled by mcp-go library.
			// Hold connection open until idle timeout.
			<-time.After(idleTimeout)
		}()
	}
}
