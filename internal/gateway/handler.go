package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/budget"
	"github.com/keylatch/keylatch/internal/gateway/approval"
	"github.com/keylatch/keylatch/internal/gateway/redact"
	"github.com/keylatch/keylatch/internal/gateway/staticbroker"
	"github.com/keylatch/keylatch/internal/gateway/substitution"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/telemetry"
)

// errorResponse is the machine-readable gateway error format.
// All 401/403/404 errors use this shape — value-free.
type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// writeError writes a JSON error response with code and message.
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, _ := json.Marshal(errorResponse{Error: code, Message: message})
	_, _ = w.Write(b)
}

// gatewayHandler is the main request handler for /api/<provider>/<action> and /sdk/<...> routes.
//
// Handler flow (per plan §3):
//  1. Parse Authorization: Bearer <jwt>
//  2. Read X-Keylatch-FD-Nonce header (base64-decoded, 32 bytes if set)
//  3. token.Verify → t | 401 on failure
//  4. router.Match(method, path) → rt | 404
//  5. Check t.Capabilities ⊇ {rt.Capability} | 403
//     5b. LLM-session gate (from JWT claim, NOT from server env)
//  6. policy check (Phase 9: always allow via CheckPolicy stub)
//     6-budget. per-actor budget CheckAndRecord | 429 with value-free denial receipt
//     6a. substitution.CheckRequest | 400
//  7. vault.Get (canonical path for provider) → rootCredential
//  8. broker.Exchange → accessToken | 503 on ErrVaultLocked / ErrExchangeUnsupported
//  9. Build upstream request + inject auth
//  10. http.Client.Do(upstream) | 503 on transport error
//  11. redact.Headers + redact.Body
//  12. audit.Log(ActionGatewayCall, ...)
//  13. Write redacted response to client
func (s *Server) gatewayHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	outcome := audit.OutcomeError
	defer func() {
		if s.opts.Metrics == nil {
			return
		}
		switch outcome {
		case audit.OutcomeOK:
			s.opts.Metrics.GatewayRequestsOK.Add(1)
		case audit.OutcomeDenied:
			s.opts.Metrics.GatewayRequestsDenied.Add(1)
		default:
			s.opts.Metrics.GatewayRequestsError.Add(1)
		}
		s.opts.Metrics.GatewayLatencyTotalMs.Add(time.Since(start).Milliseconds())
	}()
	ctx := r.Context()

	// Only handle paths starting with /api/ or /sdk/.
	if !strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/sdk/") {
		writeError(w, http.StatusNotFound, "unsupported_by_keylatch_gateway", "path not found")
		outcome = audit.OutcomeDenied
		return
	}

	// Step 1: Parse Authorization: Bearer <jwt>.
	authHeader := r.Header.Get("Authorization")
	jwtStr := ""
	if strings.HasPrefix(authHeader, "Bearer ") {
		jwtStr = strings.TrimPrefix(authHeader, "Bearer ")
	}
	if jwtStr == "" {
		writeError(w, http.StatusUnauthorized, "missing_token", "authorization token required")
		outcome = audit.OutcomeDenied
		return
	}

	// Step 3: Verify JWT.
	t, err := token.Verify(jwtStr, r, s.opts.SigningKey, s.opts.TokenStorePath)
	if err != nil {
		code := "token_invalid"
		switch {
		case isErr(err, token.ErrTokenExpired):
			code = "token_expired"
		case isErr(err, token.ErrTokenRevoked):
			code = "token_revoked"
		case isErr(err, token.ErrTokenExhausted):
			code = "token_exhausted"
		case isErr(err, token.ErrFDNonceMismatch):
			code = "fd_nonce_mismatch"
		}
		writeError(w, http.StatusUnauthorized, code, "token verification failed")
		s.logAudit(ctx, audit.ActionGatewayCall, audit.OutcomeDenied, map[string]any{
			"error": code,
		})
		outcome = audit.OutcomeDenied
		return
	}

	// Step 4: Route match.
	rt, ok := s.router.Match(r.Method, r.URL.Path)
	if !ok {
		writeError(w, http.StatusNotFound, "unsupported_by_keylatch_gateway", "no gateway route for this provider/action")
		outcome = audit.OutcomeDenied
		return
	}

	// Step 5: Capability check.
	if !token.HasCapability(t, rt.Capability) {
		writeError(w, http.StatusForbidden, "capability_mismatch", "token does not have required capability")
		s.logAudit(ctx, audit.ActionGatewayCall, audit.OutcomeDenied, map[string]any{
			"error":      "capability_mismatch",
			"capability": rt.Capability,
		})
		outcome = audit.OutcomeDenied
		return
	}

	// Step 5b: LLM-session gate (from JWT claim, NEVER from server env — S9-13).
	if t.LLMSession {
		// Block read-class capabilities.
		if token.IsReadClassCap(rt.Capability) {
			writeError(w, http.StatusForbidden, "llm_session_read_blocked", "read-class capabilities blocked in LLM session")
			s.logAudit(ctx, audit.ActionGatewayCall, audit.OutcomeDenied, map[string]any{
				"error": "llm_session_read_blocked",
			})
			outcome = audit.OutcomeDenied
			return
		}
		// Block routes with LLMSessionDeny.
		if rt.LLMSessionDeny {
			writeError(w, http.StatusForbidden, "llm_session_deny", "this action is denied in LLM sessions")
			s.logAudit(ctx, audit.ActionGatewayCall, audit.OutcomeDenied, map[string]any{
				"error": "llm_session_deny",
			})
			outcome = audit.OutcomeDenied
			return
		}
		// S11-19: direct_classic_sandboxed in LLM sessions requires two-person approval.
		// If the token was minted with ApprovalRootHMAC set (sandboxed approval path)
		// but TwoPerson is false, block the request.
		if t.ApprovalRootHMAC != "" && !t.TwoPerson {
			writeError(w, http.StatusForbidden, "llm_session_requires_two_person_approval",
				"direct_classic_sandboxed in an LLM session requires two-person approval")
			s.logAudit(ctx, audit.ActionGatewayCall, audit.OutcomeDenied, map[string]any{
				"error": "llm_session_requires_two_person_approval",
			})
			outcome = audit.OutcomeDenied
			return
		}
	}

	// Step 6: Policy check (Phase 9: pass-through; full policy enforcement in later phase).
	// Placeholder — no policy evaluation yet.

	// Step 6-budget: per-actor budget enforcement. CheckAndRecord is atomic
	// (no TOCTOU between check and record, C-4); the actor identity comes from
	// the verified JWT claim, never from a client-controlled header. Denials
	// return a value-free receipt with an HMAC'd actor ID.
	if s.budget != nil {
		if budgetErr := s.budget.CheckAndRecord(ctx, t.Actor, rt.Capability, 1); budgetErr != nil {
			receipt := budget.BudgetDenialReceipt{
				ActorHMAC:  budget.HashActor(s.actorHashKey, t.Actor),
				Capability: rt.Capability,
				LimitType:  "request_budget",
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			rb, _ := json.Marshal(receipt)
			_, _ = w.Write(rb)
			s.logAudit(ctx, audit.ActionGatewayCall, audit.OutcomeDenied, map[string]any{
				"error":      "budget_exceeded",
				"capability": rt.Capability,
			})
			outcome = audit.OutcomeDenied
			return
		}
	}

	// Step 6-SSRF: SSRF gate (FIND2-017). Validate the route-resolved upstream
	// host against the provider allowlist and IP deny-ranges before any
	// outbound request. Pure HTTP middleware cannot do this because the
	// provider ID and upstream host are only known after router.Match() above.
	if s.ssrfGate != nil {
		if err := s.ssrfGate.Validate(rt.Provider, rt.UpstreamHost); err != nil {
			writeError(w, http.StatusForbidden, "ssrf_blocked", "upstream host rejected by SSRF gate")
			s.logAudit(ctx, audit.ActionGatewayCall, audit.OutcomeDenied, map[string]any{
				"error":    "ssrf_blocked",
				"provider": rt.Provider,
			})
			outcome = audit.OutcomeDenied
			return
		}
	}

	// T02: Remove the Keylatch Authorization header before substitution checks run
	// so that substitution.CheckRequest does not see the session JWT as a
	// provider API key substitution attempt. The JWT has already been verified
	// and consumed above; it must not be forwarded to the upstream.
	r.Header.Del("Authorization")

	// Step 6a: Substitution prevention (S9-16).
	if kind, subErr := substitution.CheckRequest(r, rt.UpstreamHost, rt.AllowedParams, false); subErr != nil {
		writeError(w, http.StatusBadRequest, "substitution_blocked", "substitution attempt detected")
		s.logAudit(ctx, audit.ActionSubstitutionBlocked, audit.OutcomeDenied, map[string]any{
			"kind": kind,
		})
		outcome = audit.OutcomeDenied
		return
	}

	// Step 7: Read body (size-limited to default max).
	body, err := io.ReadAll(io.LimitReader(r.Body, rt.MaxBodyBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "body_read_error", "failed to read request body")
		return
	}
	if int64(len(body)) > rt.MaxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds maximum size")
		return
	}

	// Step 7: vault.Get — read root credential from vault (T01).
	//
	// T-04-01 audit: vault.Get is value-bearing. Guard coverage:
	//   (a) The caller must hold a valid gateway JWT (verified in step 3). The JWT
	//       is only minted by DispatchRunner.Run after it has passed the CLI-level
	//       LLM session guard (GuardRuntime). LLM sessions receive gateway_typed
	//       tokens; the JWT's LLMSession=true flag further restricts which routes
	//       the token can reach (step 5b). In an LLM session, read-class and
	//       LLMSessionDeny routes are blocked before vault.Get is called (steps 5b).
	//   (b) Even when vault.Get succeeds, the root credential bytes are exchanged
	//       for a broker access token (step 8) and then zeroed (deferred below).
	//       The raw credential never reaches the child process or the HTTP response.
	//
	// This call site is guarded by the JWT cap check and LLM-session route
	// restrictions. No additional guard is required here.
	//
	// Inject audit emitter so vault.Get can emit ActionRead events.
	if s.opts.AuditLogger != nil {
		ctx = audit.WithEmitter(ctx, audit.AsEmitter(s.opts.AuditLogger))
	}
	var rootCredential []byte
	if s.vault != nil && rt.SecretRef != "" {
		var vaultErr error
		rootCredential, _, vaultErr = s.vault.Get(ctx, rt.SecretRef)
		if vaultErr != nil {
			if errors.Is(vaultErr, backend.ErrNotFound) {
				writeError(w, http.StatusUnauthorized, "credential_not_found", "no credential for route")
				outcome = audit.OutcomeDenied
				return
			}
			writeError(w, http.StatusServiceUnavailable, "vault_error", "vault unavailable")
			if s.opts.Metrics != nil {
				s.opts.Metrics.VaultErrorsTotal.Add(1)
			}
			return
		}
	}
	// When vault is nil (tests without vault), rootCredential stays nil and
	// the broker's static_gateway_only strategy treats it as an empty credential.
	// rootCredential is zeroed in the single defer below (S9-2) — do not add a second defer here.

	// Step 8: Exchange credential via broker.
	accessToken, err := s.broker.Exchange(ctx, staticbroker.ExchangeSpec{
		Strategy:       string(rt.ExchangeStrategy),
		RootCredential: rootCredential,
		Actor:          t.Actor,
		Capability:     rt.Capability,
		TTL:            1 * time.Hour,
	})
	if err != nil {
		if isErr(err, staticbroker.ErrVaultLocked) {
			writeError(w, http.StatusServiceUnavailable, "vault_locked", "vault is locked")
			return
		}
		if isErr(err, staticbroker.ErrExchangeUnsupported) {
			// S9-19c: never fallback; documented remediation.
			writeError(w, http.StatusServiceUnavailable, "exchange_unsupported",
				"exchange strategy unsupported in Phase 9. Remediation: use static_gateway_only or upgrade to Phase 13.")
			return
		}
		writeError(w, http.StatusServiceUnavailable, "exchange_error", "credential exchange failed")
		return
	}
	// S9-2: zero root credential bytes after use.
	defer func() {
		for i := range rootCredential {
			rootCredential[i] = 0
		}
		accessToken.Zero()
	}()

	// Step 9: Build upstream request.
	upstreamURL := "https://" + rt.UpstreamHost + rt.UpstreamPath //nolint:gosec // G704: UpstreamHost is validated by ssrfGate.Validate above before this point
	upstreamMethod := rt.Method
	if upstreamMethod == "" {
		upstreamMethod = "POST"
	}
	upstreamReq, err := http.NewRequestWithContext(ctx, upstreamMethod, upstreamURL, strings.NewReader(string(body))) //nolint:gosec // G704: upstreamURL built from SSRF-gate-validated UpstreamHost
	if err != nil {
		writeError(w, http.StatusInternalServerError, "upstream_build_error", "failed to build upstream request")
		return
	}

	// Copy safe headers from incoming request.
	for k, vv := range r.Header {
		lower := strings.ToLower(k)
		// Skip auth and keylatch-internal headers.
		if lower == "authorization" || strings.HasPrefix(lower, "x-keylatch-") {
			continue
		}
		for _, v := range vv {
			upstreamReq.Header.Add(k, v)
		}
	}

	// Inject auth per AuthPlacement.
	injectAuth(upstreamReq, rt.AuthPlacement, accessToken.Value)

	// Step 10: Execute upstream request using the pre-built per-provider client.
	// Lookup by provider to reuse TLS sessions and connection pool (gap P1).
	client := s.httpClients[rt.Provider]
	if client == nil {
		client = s.defaultHTTPClient
	}
	resp, err := client.Do(upstreamReq) //nolint:gosec // G704: upstreamReq URL was built from SSRF-gate-validated host above
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "upstream_error", "upstream request failed")
		s.logAudit(ctx, audit.ActionGatewayCall, audit.OutcomeError, map[string]any{
			"provider": rt.Provider,
		})
		return
	}
	defer resp.Body.Close()

	// Read response body.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, rt.MaxBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream_read_error", "failed to read upstream response")
		return
	}

	// Step 11: Redact response.
	// Leakage reduction only, not a primary security control.
	redactedHeaders := redact.Headers(resp.Header)

	// Collect redaction patterns from route.
	var patterns []string
	for _, rule := range rt.Redaction {
		patterns = append(patterns, rule.Pattern)
	}

	redactedBody := redact.Body(rt.Provider, respBody, redact.MaskingProfile(rt.MaskingProfile), patterns)

	// Label untrusted content if applicable.
	if rt.UntrustedContentSource != "" {
		redactedBody = redact.LabelUntrustedContent(redactedBody, rt.UntrustedContentSource)
	}

	// Step 12: Audit log and telemetry.
	durationMS := time.Since(start).Milliseconds()
	s.logAudit(ctx, audit.ActionGatewayCall, audit.OutcomeOK, map[string]any{
		"provider":    rt.Provider,
		"capability":  rt.Capability,
		"status_code": resp.StatusCode,
		"duration_ms": durationMS,
	})
	sink := s.telemetrySink
	if sink == nil {
		sink = telemetry.NoopSink{}
	}
	telemetry.GatewayRequestCompleted(ctx, sink, rt.Provider, "allowed", durationMS)
	outcome = audit.OutcomeOK

	// Step 13: Write redacted response to client.
	for k, vv := range redactedHeaders {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(redactedBody) //nolint:gosec // G705: body is run through redact.Body which strips secrets; this is an API gateway, not an HTML context
}

// approveHandler proxies to approval.Approve.
func (s *Server) approveHandler(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.URL.Path, "/approve/")
	if tok == "" {
		writeError(w, http.StatusBadRequest, "missing_token", "approval token required")
		return
	}
	if err := approval.Approve(r.Context(), s.opts.ApprovalsDir, tok); err != nil {
		writeError(w, http.StatusBadRequest, "approval_error", "failed to approve")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"approved"}`)
}

// approvalsHandler returns pending approvals.
func (s *Server) approvalsHandler(w http.ResponseWriter, r *http.Request) {
	pending, err := approval.Pending(r.Context(), s.opts.ApprovalsDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "approvals_error", "failed to list approvals")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	b, _ := json.Marshal(pending)
	_, _ = w.Write(b)
}

// injectAuth injects the access token into the upstream request per AuthPlacement.
func injectAuth(req *http.Request, placement registry.AuthPlacement, tokenBytes []byte) {
	if len(tokenBytes) == 0 {
		return
	}
	tokenStr := string(tokenBytes)

	switch placement.In {
	case "header":
		if placement.Scheme != "" {
			req.Header.Set(placement.Name, placement.Scheme+" "+tokenStr)
		} else {
			req.Header.Set(placement.Name, tokenStr)
		}
	case "query":
		q := req.URL.Query()
		q.Set(placement.Name, tokenStr)
		req.URL.RawQuery = q.Encode()
	case "body":
		// Phase 9: body injection not yet implemented; use header fallback.
		req.Header.Set("Authorization", "Bearer "+tokenStr)
	default:
		// Default: Bearer header.
		req.Header.Set("Authorization", "Bearer "+tokenStr)
	}
}

// isErr checks errors with errors.Is semantics.
func isErr(err, target error) bool {
	return errors.Is(err, target)
}

// logAudit writes an audit event; safe when AuditLogger is nil.
func (s *Server) logAudit(ctx context.Context, action audit.Action, outcome audit.Outcome, extra map[string]any) {
	if s.opts.AuditLogger == nil {
		return
	}
	ev := audit.Event{
		Timestamp: time.Now().UTC(),
		Action:    action,
		Outcome:   outcome,
		Extra:     extra,
	}
	_ = s.opts.AuditLogger.Log(ctx, ev)
}
