// Package gateway implements the Phase 9 local typed provider gateway server.
//
// Security invariants:
//   - S9-1: gateway binds to 127.0.0.1 only by default.
//   - S9-2: root credential bytes are zeroed after upstream call returns.
//   - S9-9: no /debug, /admin, /health/raw endpoints.
//   - S9-13: LLMSession derived from JWT claim, NEVER from gateway's os.Getenv.
//   - S9-15: child env contains ONLY KEYLATCH_SESSION_TOKEN + KEYLATCH_GATEWAY_URL.
//   - S9-16: substitution prevention enforced on every request.
//   - S9-19c: ErrExchangeUnsupported → 503 with Remediation string; never fallback to direct_classic_sandboxed.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/gateway/route"
	"github.com/keylatch/keylatch/internal/gateway/staticbroker"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/telemetry"
	"github.com/keylatch/keylatch/internal/ui"
	"github.com/keylatch/keylatch/internal/version"
)

// newProviderHTTPClient returns a tuned *http.Client for a provider.
// One client is created per provider at server startup (gap P1): this enables
// TLS session reuse and connection pooling across requests to the same host.
func newProviderHTTPClient() *http.Client {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: 25 * time.Second}
}

// Mode describes how the gateway runs.
type Mode string

const (
	ModeLocalProcess Mode = "local_process"
	ModeDocker       Mode = "docker"
)

// VaultReader is the minimal interface the gateway needs to read credentials.
// This avoids a direct dependency on backend.Backend from the gateway package,
// keeping import cycles away and allowing stub injection in tests.
type VaultReader interface {
	Get(ctx context.Context, path string) ([]byte, backend.Meta, error)
}

// ServerOptions configures a Gateway Server.
type ServerOptions struct {
	Bind              string // default "127.0.0.1:7878"; NEVER "0.0.0.0" except --unsafe-bind-all + !LLM
	PolicyPath        string
	SigningKey        []byte // 32-byte; from gateway/signing.key
	AuditLogger       *audit.Logger
	Mode              Mode
	Env               llmcontext.Lookup
	ApprovalsDir      string
	TokenStorePath    string
	AllowExternalBind bool // S9-1: requires explicit opt-in AND non-LLM session
	// Vault is the credential store. When nil and SecretRef is non-empty, the
	// handler skips vault lookup and passes an empty credential to the broker.
	Vault VaultReader
	// OverrideHTTPClient replaces ALL per-provider and default HTTP clients.
	// Use only in tests to intercept upstream calls.
	OverrideHTTPClient *http.Client

	// TelemetrySink receives anonymised usage events. If nil, events are discarded.
	TelemetrySink telemetry.Sink

	Metrics *ui.MetricsCollector
}

// Server is the local gateway HTTP server.
type Server struct {
	opts     ServerOptions
	router   *route.Router
	broker   *staticbroker.Broker
	ssrfGate *SSRFGate
	httpSrv  *http.Server
	vault    VaultReader
	// httpClients is a pre-built pool of HTTP clients keyed by provider name.
	// One client per provider enables TLS session reuse and connection pooling
	// across requests to the same upstream host (gap P1).
	httpClients map[string]*http.Client
	// defaultHTTPClient is used for providers not in httpClients.
	defaultHTTPClient *http.Client
	// telemetrySink receives anonymised usage events. nil → NoopSink.
	telemetrySink telemetry.Sink
}

// RuntimeDecision describes the routing + credential decision for a request.
type RuntimeDecision struct {
	Runtime    string
	Credential string // "keylatch_session_token"|"provider_ephemeral"|"provider_root"
	PolicyID   string
	ApprovalID string
	Reason     string
	Warnings   []string
}

// RuntimeReceipt is the value-free receipt returned to callers.
type RuntimeReceipt struct {
	Runtime         string   `json:"runtime"`
	ActorHMAC       string   `json:"actor_hmac"`
	Connection      string   `json:"connection"`
	Capability      string   `json:"capability"`
	CommandHMAC     string   `json:"command_hmac,omitempty"`
	CWDHMAC         string   `json:"cwd_hmac,omitempty"`
	PolicyDecision  string   `json:"policy_decision"`
	CredentialShape string   `json:"credential_shape"`
	TokenAccessor   string   `json:"token_accessor,omitempty"`
	AllowedHosts    []string `json:"allowed_hosts,omitempty"`
	TTLSeconds      int      `json:"ttl_seconds,omitempty"`
	MaxUses         int      `json:"max_uses,omitempty"`
	ExitCode        int      `json:"exit_code,omitempty"`
	DurationMS      int64    `json:"duration_ms,omitempty"`
}

// New creates and configures a Gateway Server.
//
// - Compiles routes from registry.List() (all gateway-supporting templates).
// - Validates SigningKey length == 32.
// - S9-1: refuses to bind !127.0.0.1 unless AllowExternalBind AND !LLM session.
// - Creates broker, registers it as vault lock subscriber (stub for Phase 9).
func New(opts ServerOptions) (*Server, error) {
	// Validate signing key.
	if len(opts.SigningKey) != 32 {
		return nil, fmt.Errorf("gateway: signing key must be 32 bytes")
	}

	// Default bind address.
	if opts.Bind == "" {
		opts.Bind = "127.0.0.1:7878"
	}

	// S9-1: refuse non-loopback bind unless explicitly opted in AND not LLM session.
	if !isLoopbackBind(opts.Bind) {
		if !opts.AllowExternalBind {
			return nil, fmt.Errorf("gateway: S9-1: refusing non-loopback bind %q — use --unsafe-bind-all to override (non-LLM sessions only)", opts.Bind)
		}
		// Check LLM session.
		env := opts.Env
		if env == nil {
			env = llmcontext.DefaultLookup
		}
		if llmcontext.IsLLMSession(env) {
			return nil, fmt.Errorf("gateway: S9-1: refusing non-loopback bind in LLM session")
		}
	}

	// Compile routes from all registered templates.
	templates := registry.List()
	router, err := route.Compile(templates)
	if err != nil {
		return nil, fmt.Errorf("gateway: compile routes: %w", err)
	}

	b := staticbroker.New()

	// Build per-provider HTTP client pool (gap P1).
	// One tuned *http.Client per provider enables TLS session reuse and
	// connection pooling; allocating a new client per request prevents both.
	//
	// OverrideHTTPClient (tests only) replaces all clients with the provided one.
	defaultClient := newProviderHTTPClient()
	if opts.OverrideHTTPClient != nil {
		defaultClient = opts.OverrideHTTPClient
	}
	httpClients := make(map[string]*http.Client)
	for _, tmpl := range templates {
		provider := tmpl.Provider
		if provider != "" {
			if _, exists := httpClients[provider]; !exists {
				if opts.OverrideHTTPClient != nil {
					httpClients[provider] = opts.OverrideHTTPClient
				} else {
					httpClients[provider] = newProviderHTTPClient()
				}
			}
		}
	}

	s := &Server{
		opts:              opts,
		router:            router,
		broker:            b,
		ssrfGate:          NewSSRFGate(),
		vault:             opts.Vault,
		httpClients:       httpClients,
		defaultHTTPClient: defaultClient,
		telemetrySink:     opts.TelemetrySink,
	}

	// hostOverrideBlockerMiddleware is configured with an empty allowedHosts
	// list. The middleware then enforces only the strong subset of its rules:
	// it blocks X-Forwarded-Host, X-Original-URL, and X-Rewrite-URL headers.
	//
	// The Host header itself is intentionally NOT compared against the
	// provider allowlist. The gateway listens on 127.0.0.1:<port>; that is
	// the Host the client targets. The upstream destination is determined by
	// the request path (router.Match → rt.UpstreamHost), not by the inbound
	// Host header. Mixing the two concepts would reject every legitimate
	// request to the gateway.
	var allowedHosts []string

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.healthHandler)
	mux.HandleFunc("POST /approve/", s.approveHandler)
	mux.HandleFunc("GET /approvals", s.approvalsHandler)

	// Gateway proxy route (catch-all): wrap gatewayHandler with the security
	// middleware chain. Order matches the request flow: auth-blocker first
	// (reject agent-supplied credentials before any further processing), then
	// host-override blocker (reject X-Forwarded-Host etc.), then the handler
	// itself — which performs SSRF host validation after route matching.
	//
	// SSRFGate cannot run as a pure HTTP middleware because it needs the
	// route-resolved provider ID + upstream host, both of which are produced
	// by router.Match() inside gatewayHandler. The handler calls
	// s.ssrfGate.Validate(rt.Provider, rt.UpstreamHost) before any outbound
	// HTTP call.
	proxy := http.Handler(http.HandlerFunc(s.gatewayHandler))
	proxy = hostOverrideBlockerMiddleware(proxy, allowedHosts)
	proxy = authBlockerMiddleware(proxy, false /* allowSelfAuth */)
	mux.Handle("/", proxy)

	s.httpSrv = &http.Server{
		Addr:              opts.Bind,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	return s, nil
}

// Serve starts the HTTP server and blocks until ctx is cancelled.
// Graceful shutdown on ctx cancel.
func (s *Server) Serve(ctx context.Context) error {
	// Start the broker's background eviction goroutine tied to the server lifetime.
	s.broker.Start(ctx)

	errCh := make(chan error, 1)
	go func() {
		if err := s.httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpSrv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// Stop zeros the signing key slice and stops the HTTP server.
func (s *Server) Stop() error {
	// Zero signing key (S9-2).
	for i := range s.opts.SigningKey {
		s.opts.SigningKey[i] = 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.httpSrv.Shutdown(ctx)
}

// Routes returns all compiled routes.
func (s *Server) Routes() []*route.Route {
	return s.router.Routes()
}

// OnVaultLock implements the FIND2-004 invariant: when the vault is locked,
// the broker cache is flushed synchronously so that no cached tokens outlive
// the vault lock event. Callers should invoke this whenever they detect that
// the backing vault has been sealed.
func (s *Server) OnVaultLock(ctx context.Context) error {
	return s.broker.OnVaultLock(ctx)
}

// OnVaultUnlock clears the broker's locked flag after the vault is unlocked.
func (s *Server) OnVaultUnlock(ctx context.Context) error {
	return s.broker.OnVaultUnlock(ctx)
}

// healthHandler responds to GET /health with a value-free status.
// S9-9: no /health/raw endpoint.
func (s *Server) healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok","version":%q}`, version.String())
}

// isLoopbackBind returns true if the bind address is a loopback address.
// Uses net.SplitHostPort and net.ParseIP to correctly handle IPv4, IPv6, and
// bare host strings without ports.
func isLoopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// addr may not have a port — treat the whole string as the host,
		// stripping brackets for bare IPv6 literals like "[::1]".
		host = strings.TrimPrefix(strings.TrimSuffix(addr, "]"), "[")
		if host == "" {
			host = addr
		}
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
