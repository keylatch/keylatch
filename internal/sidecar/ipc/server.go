package ipc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"
)

const (
	// invalidFrameWindowDuration is the sliding window for counting invalid frames.
	invalidFrameWindowDuration = time.Minute
	// invalidFrameAlertThreshold triggers an audit alert when this many invalid
	// frames arrive within the window.
	invalidFrameAlertThreshold = 10
)

// Server is the IPC Unix-socket server. It accepts exactly one connection at
// a time (single Tauri shell instance per S14-13). On HMAC mismatch the
// connection is dropped silently without surfacing detail (S14-8).
type Server struct {
	socketPath string
	key        []byte
	registry   *MethodRegistry

	// invalidFrameCount tracks frames rejected in the current window.
	// N2: plain int64 — every access is inside windowMu.Lock().
	invalidFrameCount int64
	windowStart       time.Time
	windowMu          sync.Mutex

	listener net.Listener
	mu       sync.Mutex // guards listener
}

// NewServer creates a Server that will listen on socketPath and authenticate
// frames with hmacKey. The key is copied; the caller should zero their copy.
func NewServer(socketPath string, hmacKey []byte) (*Server, error) {
	if len(hmacKey) != 32 {
		return nil, fmt.Errorf("ipc: HMAC key must be exactly 32 bytes, got %d", len(hmacKey))
	}
	k := make([]byte, 32)
	copy(k, hmacKey)
	s := &Server{
		socketPath:  socketPath,
		key:         k,
		registry:    NewMethodRegistry(),
		windowStart: time.Now(),
	}
	return s, nil
}

// Registry returns the method registry so callers can register handlers.
func (s *Server) Registry() *MethodRegistry { return s.registry }

// Listen starts the Unix domain socket listener and serves connections.
// It blocks until ctx is cancelled.
func (s *Server) Listen(ctx context.Context) error {
	// Remove stale socket file if it exists.
	_ = os.Remove(s.socketPath)

	// M7: listenSocket sets a restrictive umask on Unix before creating the
	// socket file (platform-specific: socket_unix.go / socket_windows.go).
	ln, err := listenSocket(s.socketPath)
	if err != nil {
		return fmt.Errorf("ipc: listen on %s: %w", s.socketPath, err)
	}

	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	defer func() {
		_ = ln.Close()
		_ = os.Remove(s.socketPath)
		// Zero the key when the server shuts down.
		for i := range s.key {
			s.key[i] = 0
		}
	}()

	// Close the listener when ctx is cancelled so Accept unblocks.
	go func() {
		<-ctx.Done()
		s.mu.Lock()
		if s.listener != nil {
			_ = s.listener.Close()
		}
		s.mu.Unlock()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown
			}
			// Check for temporary errors.
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Temporary() { //nolint:staticcheck
				continue
			}
			return fmt.Errorf("ipc: accept: %w", err)
		}

		// Serve this connection synchronously (one connection at a time —
		// S14-13: single Tauri shell instance).
		s.serveConn(ctx, conn)
	}
}

// serveConn handles a single IPC connection. If a second connection arrives
// while this one is active, the server will not reach Accept again until
// serveConn returns — effectively rejecting the second connection.
func (s *Server) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close() //nolint:errcheck // defer close of IPC connection, error non-actionable on shutdown

	fr := NewFrameReader(conn, s.key)
	fw := NewFrameWriter(conn, s.key)

	for {
		var req Request
		if err := fr.Read(&req); err != nil {
			if errors.Is(err, ErrHMACMismatch) {
				s.recordInvalidFrame()
				// Drop connection silently — no error detail to caller (S14-8).
				return
			}
			// EOF or connection reset — normal teardown.
			return
		}

		resp := s.registry.Dispatch(ctx, req, fw)
		// For streaming handlers (SubscribeEvents), the handler writes frames
		// directly and returns nil result; we still write a final response.
		if err := fw.Write(resp); err != nil {
			return
		}

		if ctx.Err() != nil {
			return
		}
	}
}

// recordInvalidFrame increments the per-window counter and triggers an audit
// alert if the threshold is exceeded within the window.
func (s *Server) recordInvalidFrame() {
	s.windowMu.Lock()
	defer s.windowMu.Unlock()

	now := time.Now()
	if now.Sub(s.windowStart) > invalidFrameWindowDuration {
		// N2: plain int64 assignment — access is inside windowMu.Lock().
		s.invalidFrameCount = 0
		s.windowStart = now
	}
	s.invalidFrameCount++
	count := s.invalidFrameCount
	if count >= invalidFrameAlertThreshold {
		// Audit hook placeholder — wired to Phase 5 audit in E5-T2.
		slog.Warn("invalid HMAC frame threshold exceeded", "count", count, "window", invalidFrameWindowDuration)
		// Reset to avoid repeated alerts.
		s.invalidFrameCount = 0
		s.windowStart = now
	}
}
