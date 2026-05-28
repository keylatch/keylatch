package mcp

import (
	"context"
	"fmt"
	"log/slog"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/exec"
)

// ServeStdio starts the MCP server in stdio transport mode.
//
// FIND3-010(a): no bearer token is generated or written to stderr.
// The server exits cleanly when stdin reaches EOF (parent closed pipe).
//
// Transport note: the official SDK's StdioTransport is hardwired to
// os.Stdin / os.Stdout. For injecting custom streams in tests, use
// sdkmcp.IOTransport{Reader: r, Writer: w} instead of StdioTransport.
func (s *Server) ServeStdio(ctx context.Context, store connections.Store, runner exec.CommandRunner) error {
	if s.opts.Transport != TransportStdio {
		return fmt.Errorf("mcp: ServeStdio called with transport %q", s.opts.Transport)
	}

	srv := sdkmcp.NewServer(
		&sdkmcp.Implementation{
			Name:    "keylatch",
			Version: "1.0.0",
		},
		nil,
	)

	RegisterTools(srv, store, runner)

	// S3-1: assert exactly five tools are registered.
	s.registeredTools = len(registeredTools)
	if s.registeredTools != 5 {
		return fmt.Errorf("mcp: S3-1 violation: expected 5 tools, got %d", s.registeredTools)
	}

	// FIND3-010(a): no token printed to stderr.
	// Log only "ready" to stderr — no token substring.
	if s.opts.StderrLog {
		slog.Info("keylatch mcp ready")
	}

	// ServeStdio blocks until stdin is closed (EOF) or context is cancelled.
	// StdioTransport is hardwired to os.Stdin / os.Stdout (no custom stream injection).
	transport := &sdkmcp.StdioTransport{}
	if err := srv.Run(ctx, transport); err != nil {
		// Treat context cancellation as a clean exit.
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	return nil
}

// Serve dispatches to the appropriate transport handler based on ServerOptions.Transport.
func (s *Server) Serve(ctx context.Context, store connections.Store, runner exec.CommandRunner) error {
	switch s.opts.Transport {
	case TransportStdio:
		return s.ServeStdio(ctx, store, runner)
	case TransportTCP:
		return s.ServeTCP(ctx, store, runner)
	default:
		return fmt.Errorf("mcp: unknown transport %q", s.opts.Transport)
	}
}
