package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/ui/api"
	"github.com/keylatch/keylatch/internal/ui/csrf"
	"github.com/keylatch/keylatch/internal/ui/session"
	"github.com/keylatch/keylatch/internal/version"
)

// ServerOptions configures the UI HTTP server.
type ServerOptions struct {
	// Bind is the address to listen on. Must begin with "127.0.0.1:" unless
	// AllowExternalBind is true AND the session is not an LLM session.
	Bind string

	// SigningKey is a 32-byte key used to sign bootstrap tokens.
	SigningKey []byte

	// Scope controls which operations the UI session is permitted to perform.
	Scope UISessionScope

	// Demo enables demo mode — uses stub data and appends "demo" to /api/status.
	Demo bool

	// AllowExternalBind permits binding to non-loopback addresses.
	// Ignored if Env detects an LLM session.
	AllowExternalBind bool

	// Env is the environment lookup (for LLM session detection).
	Env llmcontext.Lookup

	// AuditLogger is optional; if nil, audit events are discarded.
	AuditLogger *audit.Logger

	// Store is the connection store (optional; nil → empty list in demo/test).
	Store connections.Store

	// WizardHandlers provides the /v1/ wizard endpoint handlers (optional; nil → stub responses).
	WizardHandlers *api.WizardHandlers

	// ReceiptStore provides the in-memory receipt ring buffer for /v1/receipts (optional; nil → empty).
	ReceiptStore *api.ReceiptStore

	// IPCSecret is the hex-encoded 32-byte secret used to authenticate POST /v1/receipts
	// (S-INV-12). If empty, the no-secret variant is used (test/demo mode only).
	IPCSecret string

	// SettingsStore holds server-validated settings (optional; nil → ephemeral default per-request).
	// T-13-05: approval TTL is server-validated and clamped server-side.
	SettingsStore *api.SettingsStore
}

// Server is the local UI HTTP server.
type Server struct {
	opts    ServerOptions
	session *session.Session
	mux     *http.ServeMux
	httpSrv *http.Server
	Metrics *MetricsCollector
}

// New creates a new UI Server. Returns an error if the bind address is invalid
// or binding to a non-loopback address would be attempted in an LLM session.
func New(opts ServerOptions) (*Server, error) {
	if opts.Env == nil {
		opts.Env = llmcontext.DefaultLookup
	}
	if opts.Bind == "" {
		opts.Bind = "127.0.0.1:7890"
	}

	// Security invariant: never bind to external interfaces in LLM session.
	// Use isLoopbackBind (same logic as gateway) to correctly handle IPv4, IPv6,
	// and localhost — not a simple string prefix check.
	isLLM := llmcontext.IsLLMSession(opts.Env)
	if !isLoopbackBind(opts.Bind) {
		if isLLM {
			return nil, fmt.Errorf("ui: external bind rejected in LLM session (S10-1)")
		}
		if !opts.AllowExternalBind {
			return nil, fmt.Errorf("ui: external bind requires --unsafe-bind-all flag")
		}
	}

	// LLM session ceiling: scope can only be status-only.
	if isLLM && opts.Scope > ScopeStatusOnly {
		opts.Scope = ScopeStatusOnly
	}

	if len(opts.SigningKey) != 32 {
		return nil, fmt.Errorf("ui: signing key must be 32 bytes, got %d", len(opts.SigningKey))
	}

	sess, err := session.New(opts.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("ui: create session: %w", err)
	}

	srv := &Server{
		opts:    opts,
		session: sess,
		mux:     http.NewServeMux(),
		Metrics: NewMetricsCollector(),
	}
	token.SetMintHook(func() { srv.Metrics.TokenMintsTotal.Add(1) })
	token.SetRevokeHook(func() { srv.Metrics.TokenRevokesTotal.Add(1) })
	srv.registerRoutes()

	srv.httpSrv = &http.Server{
		Addr:              opts.Bind,
		Handler:           chain(srv.mux, SecurityHeaders, StrictCSP),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	return srv, nil
}

// BootstrapURL returns the URL the user (or keylatch ui command) should open
// to initiate the browser session.
func (s *Server) BootstrapURL() string {
	scheme := "http"
	return s.session.URL(fmt.Sprintf("%s://%s", scheme, s.opts.Bind))
}

// Serve starts the server and blocks until ctx is cancelled, then performs a
// graceful shutdown.
func (s *Server) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.opts.Bind)
	if err != nil {
		return fmt.Errorf("ui: listen on %s: %w", s.opts.Bind, err)
	}

	errCh := make(chan error, 1)
	go func() {
		if err := s.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.httpSrv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("ui: shutdown: %w", err)
	}
	return nil
}

// registerRoutes attaches all handlers to the mux.
func (s *Server) registerRoutes() {
	// Liveness probe — value-free, no session required. Returns the
	// running version and a fixed "ok" status. Matches the gateway's
	// /health endpoint contract (S9-9: no debug info leaked, no values).
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.Handle("/metrics", s.Metrics)

	// Bootstrap exchange: one-time token → HttpOnly cookie + 303 redirect.
	// T-13-01: rate-limited to 5 failed attempts per IP before 429.
	s.mux.HandleFunc("/__bootstrap", withBootstrapRateLimit(defaultRateLimiter, s.handleBootstrap))

	// CSRF token endpoint (GET): issues a fresh CSRF token cookie.
	// T-13-01: rate-limited alongside bootstrap to prevent token enumeration.
	s.mux.HandleFunc("/api/csrf", withBootstrapRateLimit(defaultRateLimiter, s.handleCSRF))

	// Status endpoint (always available, even in LLM scope).
	statusHandler := &api.StatusHandler{
		Scope: s.opts.Scope.String(),
		Demo:  s.opts.Demo,
		Env:   s.opts.Env,
	}
	s.mux.HandleFunc("/api/status", s.requireSession(statusHandler.ServeHTTP))

	// Settings endpoint (T-13-05): approval TTL with server-side clamping.
	// Session required; CSRF required for PUT (mutations).
	settingsHandler := &api.SettingsHandler{Store: s.opts.SettingsStore}
	s.mux.HandleFunc("/api/settings", s.requireSession(csrf.Middleware(settingsHandler).ServeHTTP))

	// LLM-scope ceiling: write endpoints are NOT mounted when scope is ScopeStatusOnly.
	// They return 404 (not 403) to avoid leaking route information to LLM sessions.
	if s.opts.Scope > ScopeStatusOnly {
		// Connections (read + write, CSRF-protected).
		connectionsHandler := &api.ConnectionsHandler{
			Store:       s.opts.Store,
			AuditLogger: s.opts.AuditLogger,
		}
		s.mux.HandleFunc("/api/connections", s.requireSession(csrf.Middleware(connectionsHandler).ServeHTTP))

		// Clear all connections — registered before the /api/connections/ catch-all
		// so the mux selects the more specific path first.
		clearHandler := &api.ClearConnectionsHandler{Store: s.opts.Store}
		s.mux.HandleFunc("/api/connections/clear", s.requireSession(csrf.Middleware(clearHandler).ServeHTTP))

		connectionDetailHandler := &api.ConnectionDetailHandler{
			Store:       s.opts.Store,
			AuditLogger: s.opts.AuditLogger,
		}
		connectionDetailHandler.RuntimeTester = &api.RuntimeTestHandler{Store: s.opts.Store}
		s.mux.HandleFunc("/api/connections/", s.requireSession(csrf.Middleware(connectionDetailHandler).ServeHTTP))

		// Password manager detection (T-14-04) — session required, no CSRF (read-only).
		s.mux.HandleFunc("/api/password-managers", s.requireSession((&api.PMDetectHandler{}).ServeHTTP))

		// PM browse (T-14-05) — session required, no CSRF (read-only).
		s.mux.HandleFunc("/api/pm-browse", s.requireSession((&api.PMBrowseHandler{}).ServeHTTP))

		// Doctor endpoint — per-card health check (T-14-07).
		// Accessible as GET /api/doctor?connection=<provider>&json=true
		s.mux.HandleFunc("/api/doctor", s.requireSession((&api.DoctorHandler{}).ServeHTTP))

		// Runtime test and doctor (CSRF-protected for POST, session required).
		runtimeTestHandler := &api.RuntimeTestHandler{Store: s.opts.Store}
		s.mux.HandleFunc("/api/runtime/doctor/", s.requireSession((&api.DoctorHandler{}).ServeHTTP))

		// Connections test endpoint lives under /api/connections/{name}/test — handled by the
		// connectionDetail prefix, but we register an explicit sub-path for the runtime test handler.
		// Note: the mux uses longest-match; "/api/connections/" catches all sub-paths, so we
		// register the test handler as a suffix inside connectionDetail via its own path match.
		// For direct test access, also register under /api/connections/ (handled by connectionDetailHandler).
		_ = runtimeTestHandler // registered via connectionDetailHandler path prefix above

		// Approvals (read + write).
		approvalsHandler := &api.ApprovalsHandler{}
		s.mux.HandleFunc("/api/approvals", s.requireSession(approvalsHandler.ServeHTTP))
		s.mux.HandleFunc("/api/approvals/", s.requireSession(csrf.Middleware(approvalsHandler).ServeHTTP))

		// Gateway (scoped to ScopeAdmin+; token minting additionally requires ScopeTokenMinting).
		gatewayHandler := &api.GatewayHandler{AllowTokenMinting: s.opts.Scope >= ScopeTokenMinting}
		s.mux.HandleFunc("/api/gateway/", s.requireSession(csrf.Middleware(gatewayHandler).ServeHTTP))

		// Broker (501 stub).
		brokerHandler := &api.BrokerHandler{}
		s.mux.HandleFunc("/api/broker/", s.requireSession(csrf.Middleware(brokerHandler).ServeHTTP))

		// Audit summary (read-only).
		auditHandler := &api.AuditHandler{Logger: s.opts.AuditLogger}
		s.mux.HandleFunc("/api/audit/", s.requireSession(auditHandler.ServeHTTP))

		// Agent snippet and setup.
		agentHandler := &api.AgentHandler{
			Store: s.opts.Store,
			Env:   s.opts.Env,
		}
		s.mux.HandleFunc("/api/agent/", s.requireSession(csrf.Middleware(agentHandler).ServeHTTP))

		// ── /v1/ versioned routes ────────────────────────────────────────────
		// Aliases for existing endpoints.
		s.mux.HandleFunc("/v1/health", s.handleHealth)
		s.mux.HandleFunc("/v1/status", s.requireSession(statusHandler.ServeHTTP))
		s.mux.HandleFunc("/v1/connections", s.requireSession(csrf.Middleware(connectionsHandler).ServeHTTP))

		// Experimental feature flag endpoint — value-free, reads env var only.
		s.mux.HandleFunc("/v1/config/experimental", s.handleExperimental)

		// New wizard and readiness endpoints (T02).
		wizardHandlers := s.opts.WizardHandlers
		if wizardHandlers == nil {
			wizardHandlers = &api.WizardHandlers{}
		}
		// Wire the connection store into WizardHandlers so ConnectHandler and
		// ReadinessHandler have access to persisted credential state.
		if wizardHandlers.Store == nil && s.opts.Store != nil {
			wizardHandlers.Store = s.opts.Store
		}
		receiptStore := s.opts.ReceiptStore
		if receiptStore == nil {
			receiptStore = api.NewReceiptStore(100)
		}
		s.mux.HandleFunc("/v1/backends", s.requireSession(wizardHandlers.BackendsHandler))
		s.mux.HandleFunc("/v1/providers", s.requireSession(wizardHandlers.ProvidersHandler))
		s.mux.HandleFunc("/v1/providers/", s.requireSession(wizardHandlers.ProviderDetailHandler))
		s.mux.HandleFunc("/v1/connect", s.requireSession(csrf.Middleware(http.HandlerFunc(wizardHandlers.ConnectHandler)).ServeHTTP))
		s.mux.HandleFunc("/v1/agent/setup", s.requireSession(csrf.Middleware(http.HandlerFunc(wizardHandlers.AgentSetupHandler)).ServeHTTP))
		s.mux.HandleFunc("/v1/health/readiness", s.requireSession(wizardHandlers.ReadinessHandler))
		// /v1/receipts: GET → ring-buffer list; POST → CLI→keylatchd IPC bridge.
		// POST is loopback-only by virtue of the server binding to 127.0.0.1:7890.
		receiptsGetHandler := api.NewReceiptsHandler(receiptStore)
		receiptsPushHandler := api.NewPushReceiptsHandlerWithSecret(receiptStore, s.opts.IPCSecret)
		s.mux.HandleFunc("/v1/receipts", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				s.requireSession(receiptsGetHandler.ServeHTTP)(w, r)
			case http.MethodPost:
				receiptsPushHandler.ServeHTTP(w, r)
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
		})
		s.mux.HandleFunc("/v1/receipts/stream", s.requireSession(api.NewReceiptsStreamHandler(receiptStore).ServeHTTP))

		// /v1/approvals — reuse the existing approvalsHandler logic via a path-rewriting wrapper.
		// ApprovalsHandler dispatches on the /api/approvals prefix; rewrite /v1/ → /api/ before delegating.
		v1ApprovalsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/api" + r2.URL.Path[3:] // /v1/approvals... → /api/approvals...
			if r2.URL.RawPath != "" {
				r2.URL.RawPath = "/api" + r2.URL.RawPath[3:]
			}
			approvalsHandler.ServeHTTP(w, r2)
		})
		s.mux.HandleFunc("/v1/approvals", s.requireSession(v1ApprovalsHandler))
		s.mux.HandleFunc("/v1/approvals/", s.requireSession(csrf.Middleware(v1ApprovalsHandler).ServeHTTP))

		// SPA fallback: everything else serves the embedded SPA.
		s.mux.HandleFunc("/", NewSPAFileServer().ServeHTTP)
	} else {
		// In LLM/status-only scope: all /api/* paths return 404 explicitly
		// (security invariant: no route information leaks to LLM sessions).
		s.mux.HandleFunc("/api/", http.NotFound)
		// SPA fallback for non-API routes.
		s.mux.HandleFunc("/", NewSPAFileServer().ServeHTTP)
	}
}

// handleBootstrap exchanges the one-time bootstrap token for a session cookie.
// FIND-011: after the 303 redirect the token is consumed and never appears in
// any subsequent URL.
func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.URL.Query().Get("b")
	mac := r.URL.Query().Get("mac")

	cookieVal, err := s.session.ConsumeBootstrap(token, mac)
	if err != nil {
		http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Issue session cookie.
	s.session.SetCookie(w, cookieVal)

	// Issue CSRF token cookie.
	csrfToken, err := csrf.IssueToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	csrf.SetCookie(w, csrfToken)

	// 303 redirect to / — token no longer in any URL.
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleCSRF issues a new CSRF token.
func (s *Server) handleCSRF(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token, err := csrf.IssueToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	csrf.SetCookie(w, token)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"csrf": token})
}

// requireSession wraps a handler to enforce session cookie validation.
func (s *Server) requireSession(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := s.session.ValidateRequest(r); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// handleExperimental returns {"experimental": bool} based on KEYLATCH_EXPERIMENTAL env var.
// No session required — safe to read without credentials.
//
// NOTE: This handler reads KEYLATCH_EXPERIMENTAL directly instead of calling
// cli.IsExperimentalEnabled(settings). As a result, users who rely solely on
// custom.experimental_gated = true (without also setting KEYLATCH_EXPERIMENTAL=1)
// will see {"experimental": false} from this endpoint. The fix requires threading
// runtime.EffectiveSettings through ServerOptions and into this handler. Tracked
// as a known limitation in docs/experimental.md.
func (s *Server) handleExperimental(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	experimental := os.Getenv("KEYLATCH_EXPERIMENTAL") == "1"
	_ = json.NewEncoder(w).Encode(map[string]bool{"experimental": experimental})
}

// handleHealth returns a value-free liveness response. No authentication
// is required so external probes (kubelet, docker healthcheck, monitoring
// dashboards) can verify the server is alive without provisioning a
// session token. The response intentionally contains only "status" and
// "version" — no host, no scope, no audit counters.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// Use the same shape as the gateway /health endpoint for symmetry.
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": version.String(),
	})
}
