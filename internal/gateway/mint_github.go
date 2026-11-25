package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/broker/strategies"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/policy/mint"
)

// MintGitHubPath is the endpoint a session token calls to get a short-lived
// GitHub App installation token for one repository.
const MintGitHubPath = "/mint/github"

// MintGitHubCapability is the session-token capability the endpoint requires.
const MintGitHubCapability = "github.mint"

// maxMintBodyBytes bounds the request body; a mint request is a few hundred bytes.
const maxMintBodyBytes = 4096

// defaultMintPermissions is what a caller gets without naming permissions:
// push to branches and open or update pull requests, nothing administrative.
var defaultMintPermissions = map[string]string{
	"contents":      "write",
	"pull_requests": "write",
	"metadata":      "read",
}

// GitHubMintOptions enables the mint endpoint.
type GitHubMintOptions struct {
	// Connection is the github-app connection holding app_id, private_key and
	// installation_<owner>. Namespace and Category locate it in the vault.
	Connection string
	Namespace  string
	Category   string
	// Policy is the connection's mint.github_app policy; a nil policy denies
	// every request.
	Policy *config.GitHubAppMintPolicy
	// APIBase and HTTPClient redirect GitHub calls; tests only.
	APIBase    string
	HTTPClient *http.Client
}

type mintGitHubRequest struct {
	Repository  string            `json:"repository"`
	Permissions map[string]string `json:"permissions,omitempty"`
}

type mintGitHubReply struct {
	Token       string            `json:"token"`
	ExpiresAt   string            `json:"expires_at"`
	Repository  string            `json:"repository"`
	Permissions map[string]string `json:"permissions"`
}

// mintGitHubHandler mints an installation token scoped to one repository.
// Every request needs a valid session token with MintGitHubCapability. The
// permission `administration` is never granted, whatever the policy allows,
// so a leaked token cannot change branch protection.
func (s *Server) mintGitHubHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	opts := s.opts.GitHubMint

	authHeader := r.Header.Get("Authorization")
	jwtStr, hasBearer := strings.CutPrefix(authHeader, "Bearer ")
	if !hasBearer || jwtStr == "" {
		writeError(w, http.StatusUnauthorized, "missing_token", "authorization token required")
		return
	}
	t, err := token.Verify(jwtStr, r, s.opts.SigningKey, s.opts.TokenStorePath)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "token_invalid", "token verification failed")
		s.logAudit(ctx, audit.ActionMint, audit.OutcomeDenied, map[string]any{"error": "token_invalid"})
		return
	}
	if !token.HasCapability(t, MintGitHubCapability) {
		writeError(w, http.StatusForbidden, "capability_mismatch", "token does not have required capability")
		s.logAudit(ctx, audit.ActionMint, audit.OutcomeDenied, map[string]any{"error": "capability_mismatch"})
		return
	}

	req, err := decodeMintRequest(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	mreq := mint.Request{Repository: req.Repository, Permissions: req.Permissions}
	if err := mint.CheckGitHubApp(opts.Policy, mint.CallerService, mreq); err != nil {
		writeError(w, http.StatusForbidden, "mint_denied", "mint denied by policy")
		s.logMint(ctx, opts, mreq, time.Time{}, audit.OutcomeDenied, "policy_denied")
		return
	}

	emitter := audit.AsEmitter(s.opts.AuditLogger)
	if err := audit.Ready(emitter); err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "the audit log is not available")
		return
	}
	if s.vault == nil {
		writeError(w, http.StatusServiceUnavailable, "vault_not_configured", "gateway has no vault configured")
		return
	}

	strategy, err := s.githubAppStrategy(ctx, opts, req.Repository)
	if err != nil {
		code, status := "vault_error", http.StatusServiceUnavailable
		if errors.Is(err, backend.ErrNotFound) {
			code, status = "credential_not_found", http.StatusUnauthorized
		}
		writeError(w, status, code, "the GitHub App credential is not available")
		return
	}

	tok, err := strategy.MintScoped(ctx, strategies.GitHubAppScope{Repository: req.Repository, Permissions: req.Permissions}, mint.MaxLifetime(opts.Policy))
	if err != nil {
		reason := "github_error"
		if errors.Is(err, strategies.ErrScopeMismatch) {
			reason = "scope_mismatch"
		}
		s.logMint(ctx, opts, mreq, time.Time{}, audit.OutcomeError, reason)
		writeError(w, http.StatusBadGateway, "mint_failed", "GitHub did not issue a matching token")
		return
	}
	defer tok.Zero()

	if err := emitter.Emit(ctx, mintEvent(opts, mreq, tok.ExpiresAt, audit.OutcomeOK, "")); err != nil {
		_ = strategy.Revoke(ctx, tok.Token)
		writeError(w, http.StatusInternalServerError, "audit_failed", "the mint could not be audited; the token was revoked")
		return
	}

	out, err := json.Marshal(mintGitHubReply{
		Token:       string(tok.Token),
		ExpiresAt:   tok.ExpiresAt.UTC().Format(time.RFC3339),
		Repository:  req.Repository,
		Permissions: tok.Permissions,
	})
	if err != nil {
		_ = strategy.Revoke(ctx, tok.Token)
		writeError(w, http.StatusInternalServerError, "encode_failed", "failed to encode the reply")
		return
	}
	defer clear(out)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

func decodeMintRequest(w http.ResponseWriter, r *http.Request) (mintGitHubRequest, error) {
	var req mintGitHubRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxMintBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, errors.New("body must be JSON: {\"repository\":\"owner/name\",\"permissions\":{...}}")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return req, errors.New("body must be a single JSON object")
	}
	if _, _, err := mint.ParseRepository(req.Repository); err != nil {
		return req, err
	}
	if len(req.Permissions) == 0 {
		req.Permissions = maps.Clone(defaultMintPermissions)
	}
	for k, v := range req.Permissions {
		if k == "administration" {
			return req, errors.New("the administration permission is never granted")
		}
		if _, _, err := mint.ParsePermission(k + "=" + v); err != nil {
			return req, err
		}
	}
	return req, nil
}

func (s *Server) githubAppStrategy(ctx context.Context, opts *GitHubMintOptions, repo string) (*strategies.GitHubAppInstallationStrategy, error) {
	read := func(path string) ([]byte, error) {
		v, _, err := s.vault.Get(ctx, path)
		if err == nil && len(v) == 0 {
			return nil, backend.ErrNotFound
		}
		return v, err
	}
	owner, _, _ := strings.Cut(repo, "/")
	inst, err := read(connections.ConfigFieldPath(opts.Namespace, opts.Category, opts.Connection, "installation_"+strings.ToLower(owner)))
	if err != nil {
		return nil, err
	}
	appID, err := read(connections.ConfigFieldPath(opts.Namespace, opts.Category, opts.Connection, "app_id"))
	if err != nil {
		return nil, err
	}
	keyPEM, err := read(connections.SecretFieldPath(opts.Namespace, opts.Category, opts.Connection, "private_key"))
	if err != nil {
		return nil, err
	}
	key, err := strategies.ParseGitHubAppPrivateKey(keyPEM)
	clear(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("gateway: github app key: %w", err)
	}
	base := opts.APIBase
	if base == "" {
		base = strategies.DefaultGitHubAPIBase
	}
	sopts := []strategies.GitHubAppOption{strategies.WithGitHubAPIBase(base)}
	if opts.HTTPClient != nil {
		sopts = append(sopts, strategies.WithGitHubHTTPClient(opts.HTTPClient))
	}
	return strategies.NewGitHubAppInstallationStrategy(strings.TrimSpace(string(appID)), strings.TrimSpace(string(inst)), key, sopts...), nil
}

func mintEvent(opts *GitHubMintOptions, req mint.Request, expiresAt time.Time, outcome audit.Outcome, reason string) audit.Event {
	perms := make([]string, 0, len(req.Permissions))
	for _, k := range slices.Sorted(maps.Keys(req.Permissions)) {
		perms = append(perms, k+"="+req.Permissions[k])
	}
	extra := map[string]any{
		"connection":  opts.Connection,
		"namespace":   opts.Namespace,
		"repository":  req.Repository,
		"permissions": strings.Join(perms, ","),
		"caller_kind": string(mint.CallerService),
	}
	if !expiresAt.IsZero() {
		extra["expires_at"] = expiresAt.UTC().Format(time.RFC3339)
	}
	if reason != "" {
		extra["reason"] = reason
	}
	return audit.Event{
		Timestamp:   time.Now().UTC(),
		Action:      audit.ActionMint,
		Outcome:     outcome,
		RuntimeMode: "gateway",
		Extra:       extra,
	}
}

func (s *Server) logMint(ctx context.Context, opts *GitHubMintOptions, req mint.Request, expiresAt time.Time, outcome audit.Outcome, reason string) {
	if s.opts.AuditLogger == nil {
		return
	}
	_ = s.opts.AuditLogger.Log(ctx, mintEvent(opts, req, expiresAt, outcome, reason))
}
