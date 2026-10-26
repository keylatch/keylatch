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

// Server is the IPC Unix-socket server with bounded concurrent connections.
// On HMAC mismatch the
// connection is dropped silently without surfacing detail.
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

	// listenSocket creates the socket owner-only (socket_unix.go /
	// socket_windows.go).
	ln, err := listenSocket(s.socketPath)
	if err != nil {
		return fmt.Errorf("ipc: listen on %s: %w", s.socketPath, err)
	}

	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()
	ctx, cancel := context.WithCancel(ctx)
	var clients sync.WaitGroup
	slots := make(chan struct{}, 16)

	defer func() {
		cancel()
		_ = ln.Close()
		clients.Wait()
		_ = os.Remove(s.socketPath)
		// Zero the key when the server shuts down.
		for i := range s.key {
			s.key[i] = 0
		}
	}()

	// Close the listener when ctx is cancelled so Accept unblocks.
	stop := context.AfterFunc(ctx, func() {
		s.mu.Lock()
		if s.listener != nil {
			_ = s.listener.Close()
		}
		s.mu.Unlock()
	})
	defer stop()

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

		select {
		case slots <- struct{}{}:
			clients.Go(func() {
				defer func() { <-slots }()
				s.serveConn(ctx, conn)
			})
		default:
			_ = conn.Close()
		}
	}
}

// serveConn authenticates each frame before dispatching it.
func (s *Server) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close() //nolint:errcheck // defer close of IPC connection, error non-actionable on shutdown
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	fr := NewFrameReader(conn, s.key)
	fw := NewFrameWriter(timedIPCWriter{conn}, s.key)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var req Request
		if err := fr.Read(&req); err != nil {
			if errors.Is(err, ErrHMACMismatch) {
				s.recordInvalidFrame()
				// Drop connection silently — no error detail to caller.
				return
			}
			// EOF or connection reset — normal teardown.
			return
		}
		_ = conn.SetReadDeadline(time.Time{})
		if req.Method == MethodSubscribeEvents {
			done := make(chan struct{})
			go func() {
				defer close(done)
				var extra [1]byte
				_, _ = conn.Read(extra[:])
				cancel()
			}()
			_ = s.registry.Dispatch(ctx, req, fw)
			cancel()
			_ = conn.Close()
			<-done
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

type timedIPCWriter struct{ net.Conn }

func (w timedIPCWriter) Write(p []byte) (int, error) {
	if err := w.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return 0, err
	}
	return w.Conn.Write(p)
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
		// Audit hook placeholder — wired to the audit system.
		slog.Warn("invalid HMAC frame threshold exceeded", "count", count, "window", invalidFrameWindowDuration)
		// Reset to avoid repeated alerts.
		s.invalidFrameCount = 0
		s.windowStart = now
	}
}
