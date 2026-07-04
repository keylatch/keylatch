// Package proxy implements the gateway_proxy runtime: a local HTTP/HTTPS
// intercepting proxy that injects provider credentials transparently.
//
// Security invariants:
//   - Hosts not in the profile allowlist receive 403.
//   - Routes not in profile allowlist receive 403.
//   - Caller-supplied Authorization headers are stripped before forwarding.
//   - Provider credentials are fetched from vault per-request; never stored.
package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/registry"
)

// defaultProxyAddr is the default proxy listen address.
const defaultProxyAddr = "127.0.0.1:7879"

// ProxyVaultReader is the minimal vault interface the proxy needs.
type ProxyVaultReader interface {
	Get(ctx context.Context, path string) ([]byte, backend.Meta, error)
}

// Server is the gateway_proxy local HTTP/HTTPS intercepting proxy.
//
// It binds on Addr, intercepts HTTP requests, strips caller-supplied credentials,
// fetches provider credentials from Vault, and forwards requests to the upstream
// with the correct Authorization header.
//
// For HTTPS, it intercepts CONNECT tunnels, mints a per-host leaf certificate
// signed by the local CA, and presents it to the client.
type Server struct {
	// Addr is the listen address. Defaults to "127.0.0.1:7879".
	Addr string
	// Profile is the proxy security profile describing allowed hosts/routes.
	Profile ProxyProfile
	// Vault provides credential lookups. When nil, an empty credential is used.
	Vault ProxyVaultReader
	// CA is the TLS certificate authority for HTTPS interception.
	CA *tlsCA
	// AuditEmitter receives audit events. May be nil.
	AuditEmitter audit.Emitter
	// Token is the per-session bearer token callers must present (the proxy
	// caller-auth check). Serve() mints one via EnsureToken if empty.
	//
	// Empty Token disables authentication — mirrors the established
	// "empty secret = disabled" pattern used by ui.ServerOptions.IPCSecret
	// (see internal/ui/api receipts handler); intended for tests only, since
	// Serve() always ensures a token is set for any real listener.
	Token string
	// client is the shared HTTP client reused across requests (S1: avoids per-request allocation).
	// Initialised lazily via clientOnce.
	client     *http.Client
	clientOnce sync.Once
	tokenOnce  sync.Once
	tokenErr   error
}

// proxyAuthHeader is the header proxy callers must present the per-session
// bearer token in (the proxy caller-auth check). "Proxy-Authorization" is the RFC 7235 standard
// header for authenticating to a forward/CONNECT proxy — deliberately
// distinct from "Authorization", which callers may legitimately (attempt to)
// set for the *upstream origin* and which this proxy already strips before
// forwarding (see routeHandler). Reusing "Authorization" for proxy-caller
// auth would conflate the two concerns and break that stripping test/guarantee.
const proxyAuthHeader = "Proxy-Authorization"

// EnsureToken lazily mints s.Token (32 random bytes, hex-encoded) if it is
// currently empty, and returns it. Safe for concurrent use. Call this before
// publishing the token to a child process so a concurrent caller can never
// observe an empty/unset token.
func (s *Server) EnsureToken() (string, error) {
	s.tokenOnce.Do(func() {
		if s.Token != "" {
			return
		}
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			s.tokenErr = fmt.Errorf("generate caller auth token: %w", err)
			return
		}
		s.Token = hex.EncodeToString(b)
	})
	return s.Token, s.tokenErr
}

// checkCallerAuth validates the per-session bearer token (the proxy caller-auth
// check — internal/proxy/server.go bound 127.0.0.1:7879 with
// no client auth, so any same-user process could drive credential
// injection). Returns true if the request is authorized.
func (s *Server) checkCallerAuth(r *http.Request) bool {
	if s.Token == "" {
		// Auth disabled — test/demo mode only (see Token doc comment).
		return true
	}
	const prefix = "Bearer "
	got := r.Header.Get(proxyAuthHeader)
	if !strings.HasPrefix(got, prefix) {
		return false
	}
	presented := strings.TrimPrefix(got, prefix)
	return subtle.ConstantTimeCompare([]byte(presented), []byte(s.Token)) == 1
}

// isLoopbackAddr returns true if addr's host resolves to loopback. Mirrors
// the isLoopbackBind helper in internal/ui and internal/gateway.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
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

// Serve starts the proxy HTTP server on s.Addr and blocks until ctx is cancelled.
// Graceful shutdown on ctx cancel.
//
// Unlike internal/ui and internal/gateway, the CONNECT proxy has no
// --listen/--unsafe-bind-all opt-in and is loopback-only, unconditionally.
// Rationale (docker-server-security hardening pass): the proxy transparently
// injects live provider credentials into whatever host the caller CONNECTs
// to, gated only by a flat host allowlist (Profile.Hosts) — there is no
// per-request, capability-scoped authorization as granular as the gateway's
// minted JWTs. Exposing that control plane to a container's host network
// would multiply the blast radius of a single compromised profile well
// beyond the UI's status surface or the gateway's scoped tokens. The proxy
// caller-auth check (below) mitigates the "any same-user process" risk; it does not
// by itself justify network exposure, so no opt-in is offered here.
func (s *Server) Serve(ctx context.Context) error {
	addr := s.Addr
	if addr == "" {
		addr = defaultProxyAddr
	}

	if !isLoopbackAddr(addr) {
		return fmt.Errorf("proxy: refusing non-loopback bind %q — the CONNECT proxy is loopback-only by design (no --listen/--unsafe-bind-all opt-in)", addr)
	}

	// Mint the per-session caller-auth bearer token before accepting any
	// connections. See checkCallerAuth.
	if _, err := s.EnsureToken(); err != nil {
		return fmt.Errorf("proxy: %w", err)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("proxy: listen %s: %w", addr, err)
	}

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           http.HandlerFunc(s.ServeHTTP),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

// ServeHTTP dispatches requests: CONNECT to handleCONNECT, everything else to
// routeHandler. This method is exported so tests can use httptest.Server.
//
// The proxy caller-auth check is enforced first, before any routing or
// host-allowlist decisions — an unauthenticated caller must not learn
// anything about the profile (not even "host not allowed" vs "unauthorized").
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.checkCallerAuth(r) {
		s.auditDeny(r.Context(), "proxy_caller_unauthenticated", r.Host)
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if r.Method == http.MethodConnect {
		s.handleCONNECT(w, r)
		return
	}
	s.routeHandler(w, r)
}

// routeHandler handles plain HTTP requests:
//  1. Enforce host allowlist.
//  2. Strip caller-supplied Authorization header.
//  3. Fetch credential from vault.
//  4. Forward to upstream; stream response back.
func (s *Server) routeHandler(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		host = h
	}

	// Step 1: host allowlist check.
	if !s.hostAllowed(host) {
		s.auditDeny(r.Context(), "host_not_allowed", host)
		http.Error(w, `{"error":"host_not_allowed"}`, http.StatusForbidden)
		return
	}

	// Step 1b: SSRF re-resolution guard.
	// Re-resolve the hostname on every request when the profile requires it.
	if s.Profile.SSRF.ResolveAndVerifyEachRequest {
		if err := s.ssrfCheck(host); err != nil {
			s.auditDeny(r.Context(), "ssrf_denied", host)
			http.Error(w, `{"error":"ssrf_denied"}`, http.StatusForbidden)
			return
		}
	}

	// Step 2: strip caller-supplied Authorization header.
	r.Header.Del("Authorization")

	// Step 3: find matching route — deny if none matches (fail-closed).
	route := s.matchRoute(r)
	if route == nil {
		s.auditDeny(r.Context(), "route_not_allowed", r.URL.Path)
		http.Error(w, `{"error":"route_not_allowed"}`, http.StatusForbidden)
		return
	}

	// Fetch credential from vault for the matched route.
	var credValue []byte
	if s.Vault != nil {
		// Extract secret path from route's AuthInjection.Value ({{ secret.<path> }} syntax).
		secretPath := parseSecretRef(route.AuthInjection.Value)
		if secretPath != "" {
			val, _, err := s.Vault.Get(r.Context(), secretPath)
			if err != nil {
				http.Error(w, `{"error":"credential_unavailable"}`, http.StatusServiceUnavailable)
				return
			}
			credValue = val
			defer zeroProxyBytes(credValue)
		}
	}

	// Build upstream request.
	upstreamURL := r.URL
	if upstreamURL.Host == "" {
		upstreamURL.Host = r.Host
	}
	if upstreamURL.Scheme == "" {
		upstreamURL.Scheme = "http"
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), r.Body)
	if err != nil {
		http.Error(w, `{"error":"upstream_build_error"}`, http.StatusInternalServerError)
		return
	}

	// Copy safe headers.
	for k, vv := range r.Header {
		lower := strings.ToLower(k)
		// proxy-authorization carries our own caller-auth bearer token
		// (checked in ServeHTTP) and must never reach the upstream provider.
		if lower == "authorization" || lower == "proxy-authorization" || strings.HasPrefix(lower, "x-keylatch-") {
			continue
		}
		for _, v := range vv {
			upstreamReq.Header.Add(k, v)
		}
	}

	// Inject credential via route's AuthInjection placement.
	if len(credValue) > 0 && route != nil {
		injectProxyCred(upstreamReq, route.AuthInjection, credValue)
	}

	// Forward using the shared per-server HTTP client (S1: avoids per-request allocation).
	resp, err := s.httpClient().Do(upstreamReq) //nolint:gosec
	if err != nil {
		http.Error(w, `{"error":"upstream_error"}`, http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	// Copy response headers.
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	// Stream response body.
	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			w.Write(buf[:n]) //nolint:errcheck
		}
		if readErr != nil {
			break
		}
	}
}

// handleCONNECT handles HTTPS CONNECT tunneling:
//  1. Enforce host allowlist.
//  2. Hijack TCP connection.
//  3. Send 200 Connection established.
//  4. Mint per-host TLS cert via CA.
//  5. Terminate TLS; replay decrypted request through routeHandler.
func (s *Server) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	bareHost, _, err := net.SplitHostPort(host)
	if err == nil {
		host = bareHost
	}

	// Host allowlist check.
	if !s.hostAllowed(host) {
		s.auditDeny(r.Context(), "host_not_allowed_connect", host)
		http.Error(w, `{"error":"host_not_allowed"}`, http.StatusForbidden)
		return
	}

	// SSRF re-resolution guard.
	if s.Profile.SSRF.ResolveAndVerifyEachRequest {
		if err := s.ssrfCheck(host); err != nil {
			s.auditDeny(r.Context(), "ssrf_denied", host)
			http.Error(w, `{"error":"ssrf_denied"}`, http.StatusForbidden)
			return
		}
	}

	// Hijack the TCP connection.
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, `{"error":"hijack_not_supported"}`, http.StatusInternalServerError)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()

	// Acknowledge the CONNECT.
	if _, err := fmt.Fprintf(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}

	// Mint per-host certificate if CA is available.
	var tlsConfig *tls.Config
	if s.CA != nil {
		cert, certErr := s.CA.CertForHost(host)
		if certErr == nil {
			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{*cert},
				MinVersion:   tls.VersionTLS12,
			} //nolint:gosec // G402: MinVersion is TLS 1.2, not insecure
		}
	}

	if tlsConfig == nil {
		// No CA: cannot terminate TLS; forward raw TCP (transparent proxy).
		upstream, dialErr := net.Dial("tcp", r.Host)
		if dialErr != nil {
			return
		}
		defer func() { _ = upstream.Close() }()
		go func() {
			if n := brw.Reader.Buffered(); n > 0 {
				buf := make([]byte, n)
				_, _ = brw.Read(buf)
				_, _ = conn.Write(buf)
			}
			bridgeTCP(conn, upstream)
		}()
		bridgeTCP(upstream, conn)
		return
	}

	// Flush any buffered bytes from the hijacked connection, then wrap in TLS.
	if n := brw.Reader.Buffered(); n > 0 {
		buf := make([]byte, n)
		_, _ = brw.Read(buf) // buffered pre-read bytes are consumed; TLS handshake follows
	}

	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer func() { _ = tlsConn.Close() }()

	// Read the decrypted HTTP request.
	decryptedReq, err := http.ReadRequest(bufio.NewReader(tlsConn))
	if err != nil {
		return
	}
	decryptedReq.URL.Scheme = "https"
	decryptedReq.URL.Host = r.Host

	// Replay through routeHandler using a synthetic ResponseWriter.
	rw := newBufferedResponseWriter()
	s.routeHandler(rw, decryptedReq)
	rw.writeResponseTo(tlsConn) //nolint:errcheck
}

// hostAllowed returns true if host is in the Profile's Hosts allowlist.
// Comparison is performed on the bare hostname (without port) so that both
// "example.com" and "example.com:443" in the Hosts list match an incoming
// request with Host: "example.com:443".
// An empty allowlist denies all (fail-closed).
func (s *Server) hostAllowed(host string) bool {
	// host is already bare (port stripped by caller).
	for _, allowed := range s.Profile.Hosts {
		// Strip port from allowlist entry for normalised comparison.
		bare := allowed
		if h, _, err := net.SplitHostPort(allowed); err == nil {
			bare = h
		}
		if bare == host || allowed == host {
			return true
		}
	}
	return false
}

// matchRoute returns the first ProxyRoute matching the request path.
// Returns nil when no route matches (fail-closed — 403 from caller).
func (s *Server) matchRoute(r *http.Request) *ProxyRoute {
	for i := range s.Profile.Routes {
		route := &s.Profile.Routes[i]
		if (route.Method == "" || route.Method == r.Method) &&
			strings.HasPrefix(r.URL.Path, route.Path) {
			return route
		}
	}
	return nil
}

// auditDeny emits a deny audit event. Safe when AuditEmitter is nil.
func (s *Server) auditDeny(ctx context.Context, reason, host string) {
	if s.AuditEmitter == nil {
		return
	}
	ev := audit.Event{
		Action:  audit.ActionGatewayCall,
		Outcome: audit.OutcomeDenied,
		Extra: map[string]any{
			"reason": reason,
			"host":   host,
		},
	}
	_ = s.AuditEmitter.Emit(ctx, ev)
}

// parseSecretRef extracts the vault path from {{ secret.<path> }} template syntax.
// Returns "" if the value is not a secret template.
func parseSecretRef(value string) string {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "{{") || !strings.HasSuffix(value, "}}") {
		return ""
	}
	inner := strings.TrimSpace(value[2 : len(value)-2])
	if !strings.HasPrefix(inner, "secret.") {
		return ""
	}
	return strings.TrimPrefix(inner, "secret.")
}

// injectProxyCred injects the credential into the request based on AuthInjection.
func injectProxyCred(req *http.Request, ai AuthInjection, cred []byte) {
	credStr := string(cred)
	switch ai.Placement {
	case "header":
		req.Header.Set(ai.Name, credStr)
	case "query":
		q := req.URL.Query()
		q.Set(ai.Name, credStr)
		req.URL.RawQuery = q.Encode()
	case "basic":
		req.SetBasicAuth(ai.Name, credStr)
	default:
		// Default: Bearer header.
		req.Header.Set("Authorization", "Bearer "+credStr)
	}
}

// zeroProxyBytes overwrites a byte slice with zeros.
func zeroProxyBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// bridgeTCP copies data from src to dst until EOF.
func bridgeTCP(dst net.Conn, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			dst.Write(buf[:n]) //nolint:errcheck
		}
		if err != nil {
			break
		}
	}
}

// httpClient returns the shared HTTP client, initialising it lazily on first call.
// Reusing a single client allows connection pooling across requests (S1).
func (s *Server) httpClient() *http.Client {
	s.clientOnce.Do(func() {
		s.client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: false}, //nolint:gosec // explicit false — not insecure
			},
			Timeout: 30 * time.Second,
		}
	})
	return s.client
}

// ssrfCheck resolves host to IPs and verifies none fall within denied private ranges.
// Returns a non-nil error if any resolved IP is in a denied range.
func (s *Server) ssrfCheck(host string) error {
	addrs, err := net.LookupHost(host)
	if err != nil {
		// Treat lookup failure as a deny — the host is unresolvable and therefore suspect.
		return fmt.Errorf("ssrf_check: cannot resolve %q: %w", host, err)
	}
	if !s.Profile.SSRF.DenyPrivateRanges {
		return nil
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		for _, network := range registry.SSRFDenyRanges {
			if network.Contains(ip) {
				return fmt.Errorf("ssrf_check: %q resolves to denied range %s", host, network)
			}
		}
	}
	return nil
}
