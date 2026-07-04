package llmcontext

// session_server.go
//
// SessionServer exposes a minimal HTTP-over-UDS server that keylatchd runs to
// answer LLM session queries from CLI child processes.
//
// Endpoints:
//
//	GET  /v1/llm-session?pid=<n>
//	  Returns {"_schema":"v1","active":bool,"agent":"","ticket":""}.
//	  The `_schema` field is load-bearing for the session contract.
//	  The `ticket` field is reserved for future use (IDE extension, out of scope v1.0.0).
//
//	POST /v1/llm-session
//	  Body: {"pid":<n>,"agent":"<name>"}
//	  Registers pid as an active LLM session.
//	  Returns {"_schema":"v1","ok":true}.
//
//	DELETE /v1/llm-session?pid=<n>
//	  Deregisters pid from the session registry.
//	  Returns {"_schema":"v1","ok":true}.
//
// Security: the socket is mode 0600 so only the daemon user (and root) can
// connect. No authentication is applied — trust is via filesystem permissions.
//
// This file imports only stdlib packages.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
)

const sessionServerSchema = "v1"

// SessionServer is a minimal HTTP server listening on a Unix domain socket.
type SessionServer struct {
	socketPath string
	registry   *SessionRegistry
	signingKey []byte // HMAC key for IssueTicket (at least 32 bytes); kept in memory only

	mu       sync.Mutex
	listener net.Listener
	httpSrv  *http.Server
}

// NewSessionServer creates a SessionServer that will listen on socketPath.
// signingKey must be at least 32 bytes; it is used by IssueTicket when a ticket
// is requested. The registry tracks active LLM sessions.
func NewSessionServer(socketPath string, signingKey []byte, registry *SessionRegistry) (*SessionServer, error) {
	if len(signingKey) < 32 {
		return nil, fmt.Errorf("llmcontext: session server signing key must be at least 32 bytes, got %d", len(signingKey))
	}
	if registry == nil {
		return nil, fmt.Errorf("llmcontext: session registry must not be nil")
	}

	key := make([]byte, 32)
	copy(key, signingKey)

	s := &SessionServer{
		socketPath: socketPath,
		registry:   registry,
		signingKey: key,
	}
	return s, nil
}

// Listen starts the UDS HTTP server. It blocks until ctx is cancelled.
// The socket file is removed on shutdown.
func (s *SessionServer) Listen(ctx context.Context) error {
	// Remove stale socket.
	_ = os.Remove(s.socketPath)

	// Set umask to 0o177 before Listen so the socket is created with mode
	// 0600 from the start, closing the TOCTOU window between Listen and Chmod.
	// restoreUmask is called immediately after Listen regardless of error.
	oldUmask := setSocketUmask()
	ln, err := net.Listen("unix", s.socketPath)
	restoreUmask(oldUmask)
	if err != nil {
		return fmt.Errorf("llmcontext: session server listen on %s: %w", s.socketPath, err)
	}
	// Explicit Chmod keeps the permission correct even on platforms where the
	// umask approach is a no-op (e.g. Windows) or when a race is unavoidable.
	if err := os.Chmod(s.socketPath, 0o600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("llmcontext: session server chmod %s: %w", s.socketPath, err)
	}

	s.mu.Lock()
	s.listener = ln
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/llm-session", s.handleSession)
	s.httpSrv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: daemonIPCTimeout,
		ReadTimeout:       daemonIPCTimeout * 4,
		WriteTimeout:      daemonIPCTimeout * 4,
	}
	s.mu.Unlock()

	defer func() {
		_ = ln.Close()
		_ = os.Remove(s.socketPath)
		for i := range s.signingKey {
			s.signingKey[i] = 0
		}
	}()

	// Cancel the server when ctx is cancelled.
	go func() {
		<-ctx.Done()
		s.mu.Lock()
		srv := s.httpSrv
		s.mu.Unlock()
		if srv != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), daemonIPCTimeout)
			defer cancel()
			_ = srv.Shutdown(shutdownCtx)
		}
	}()

	if err := s.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
		if ctx.Err() != nil {
			return nil // clean shutdown
		}
		return fmt.Errorf("llmcontext: session server: %w", err)
	}
	return nil
}

// handleSession dispatches GET, POST, and DELETE on /v1/llm-session.
func (s *SessionServer) handleSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		s.handleGet(w, r)
	case http.MethodPost:
		s.handlePost(w, r)
	case http.MethodDelete:
		s.handleDelete(w, r)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// handleGet responds to GET /v1/llm-session?pid=<n>.
func (s *SessionServer) handleGet(w http.ResponseWriter, r *http.Request) {
	pidStr := r.URL.Query().Get("pid")
	if pidStr == "" {
		http.Error(w, `{"error":"pid is required"}`, http.StatusBadRequest)
		return
	}
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		http.Error(w, `{"error":"pid must be an integer"}`, http.StatusBadRequest)
		return
	}

	active, agent := s.registry.IsActive(pid)
	resp := LLMSessionResponse{
		Schema: sessionServerSchema,
		Active: active,
		Agent:  agent,
		// Ticket is reserved for future use (IDE extension — out of scope v1.0.0).
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// sessionRegisterRequest is the POST body for registering an LLM session.
type sessionRegisterRequest struct {
	PID   int    `json:"pid"`
	Agent string `json:"agent,omitempty"`
}

// handlePost responds to POST /v1/llm-session.
func (s *SessionServer) handlePost(w http.ResponseWriter, r *http.Request) {
	var req sessionRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.PID <= 0 {
		http.Error(w, `{"error":"pid must be positive"}`, http.StatusBadRequest)
		return
	}

	s.registry.Register(req.PID, req.Agent)

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"_schema": sessionServerSchema,
		"ok":      true,
	})
}

// handleDelete responds to DELETE /v1/llm-session?pid=<n>.
func (s *SessionServer) handleDelete(w http.ResponseWriter, r *http.Request) {
	pidStr := r.URL.Query().Get("pid")
	if pidStr == "" {
		http.Error(w, `{"error":"pid is required"}`, http.StatusBadRequest)
		return
	}
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		http.Error(w, `{"error":"pid must be an integer"}`, http.StatusBadRequest)
		return
	}

	s.registry.Deregister(pid)

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"_schema": sessionServerSchema,
		"ok":      true,
	})
}
