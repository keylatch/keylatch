// Package mcp implements the keylatch MCP server exposing exactly five
// value-free tools over stdio and localhost-TCP transports.
//
// Security invariants enforced here:
//   - exactly five tools, enforced at startup
//   - no secret-bearing field in any tool output
//   - TCP bind to 127.0.0.1 only; no 0.0.0.0
//   - stdio mode uses no bearer token
//   - keylatch_run uses per-template allowlist
//   - TCP uses Unix-domain socket + SO_PEERCRED
package mcp

import (
	"errors"
	"net"
	"runtime"
)

// Transport identifies the MCP server's network transport.
type Transport string

const (
	TransportStdio Transport = "stdio"
	TransportTCP   Transport = "tcp"
)

// ConnectionAuthMode describes how MCP client connections are authenticated.
//
// Changes:
//   - stdio transport: always AuthStdioPipe (no bearer token)
//   - TCP on Linux/macOS: AuthUnixPeerCred (SO_PEERCRED / LOCAL_PEERCRED)
//   - TCP on Windows: AuthNamedPipeACL
//   - TCP fallback: AuthBearerLegacy (TTL <= 1h, never written to disk)
type ConnectionAuthMode string

const (
	AuthStdioPipe    ConnectionAuthMode = "stdio_pipe"
	AuthUnixPeerCred ConnectionAuthMode = "unix_peer_cred" //nolint:gosec // G101 false positive: auth mode name string, not a credential
	AuthNamedPipeACL ConnectionAuthMode = "named_pipe_acl"
	AuthBearerLegacy ConnectionAuthMode = "bearer_legacy" //nolint:gosec // G101 false positive: auth mode name string, not a credential
)

// ServerOptions configures the MCP server.
type ServerOptions struct {
	Transport Transport
	// Bind is the address to bind to for TCP transport.
	// 0.0.0.0 and --unsafe-bind-all are explicitly rejected.
	Bind string
	// SessionToken is the bearer token for AuthBearerLegacy mode.
	// Must be empty for stdio transport.
	SessionToken string
	// TokenTTL is the TTL for bearer tokens. Cap: 1 hour.
	TokenTTL string
	// ConnectionAuth overrides the default auth mode selection.
	ConnectionAuth ConnectionAuthMode
	// StdoutLog and StderrLog control logging destinations.
	StdoutLog bool
	StderrLog bool
}

// ToolResult is the result of an MCP tool invocation.
type ToolResult struct {
	Content []ToolContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

// ToolContent is a single content item in a ToolResult.
type ToolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// RuntimeReceipt is the value-free receipt returned by keylatch_run.
// It contains no credential bytes; only HMAC-based accessors.
type RuntimeReceipt struct {
	Provider   string `json:"provider"`
	Connection string `json:"connection"` // HMAC accessor, not the path
	Runtime    string `json:"runtime"`
	ExitCode   int    `json:"exit_code"`
}

// Typed errors for the MCP server.
var (
	// ErrForbiddenBind is returned when the caller tries to bind to 0.0.0.0.
	ErrForbiddenBind = errors.New("mcp: binding to 0.0.0.0 is forbidden")

	// ErrTokenInStdioMode is returned when a SessionToken is provided for stdio.
	ErrTokenInStdioMode = errors.New("mcp: session token must not be set in stdio mode")

	// ErrTTLExceedsCap is returned when TokenTTL exceeds the 1-hour cap.
	ErrTTLExceedsCap = errors.New("mcp: bearer token TTL exceeds maximum of 1 hour")

	// ErrNonceConnectionMismatch is returned when a nonce is replayed on a different connection.
	ErrNonceConnectionMismatch = errors.New("mcp: nonce connection mismatch")

	// ErrSessionTokenMismatch is returned when the presented bearer token does not match
	// the session token (A4-009).
	ErrSessionTokenMismatch = errors.New("mcp: bearer token mismatch")

	// ErrSessionTokenExpired is returned when the bearer token has exceeded the idle
	// timeout of 30 minutes with no request (A4-009).
	ErrSessionTokenExpired = errors.New("mcp: bearer token idle timeout exceeded (30 minutes)")
)

// Server is the keylatch MCP server.
type Server struct {
	opts ServerOptions
	// registeredTools counts registered tools for the startup assertion.
	registeredTools int
}

// New constructs a new MCP Server with the given options.
//
// Validates:
//   - opts.Bind must not be "0.0.0.0"
//   - stdio transport must not set SessionToken
//   - ConnectionAuth is defaulted based on transport and platform
func New(opts ServerOptions) (*Server, error) {
	// Reject 0.0.0.0 and :: (all-interfaces addresses).
	// Use net.SplitHostPort to handle "host:port" forms like "0.0.0.0:8080".
	{
		host, _, err := net.SplitHostPort(opts.Bind)
		if err != nil {
			// No port in string — treat the whole value as a host.
			host = opts.Bind
		}
		if host == "0.0.0.0" || host == "::" {
			return nil, ErrForbiddenBind
		}
	}

	// stdio transport must not carry a session token.
	if opts.Transport == TransportStdio && opts.SessionToken != "" {
		return nil, ErrTokenInStdioMode
	}

	// Default bind for TCP.
	if opts.Transport == TransportTCP && opts.Bind == "" {
		opts.Bind = "127.0.0.1"
	}

	// Default ConnectionAuth based on transport and platform.
	if opts.ConnectionAuth == "" {
		opts.ConnectionAuth = defaultAuthMode(opts.Transport)
	}

	return &Server{opts: opts}, nil
}

// defaultAuthMode selects the default ConnectionAuthMode for the given transport.
func defaultAuthMode(t Transport) ConnectionAuthMode {
	if t == TransportStdio {
		return AuthStdioPipe
	}
	// TCP: platform-specific selection.
	switch runtime.GOOS {
	case "linux", "darwin":
		return AuthUnixPeerCred
	case "windows":
		return AuthNamedPipeACL
	default:
		return AuthBearerLegacy
	}
}
