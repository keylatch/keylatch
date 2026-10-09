package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/broker/strategies"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/policy/mint"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/spf13/cobra"
)

const mintCapability = "tokens.mint"

// Replaced in tests.
var (
	mintGitHubAPIBase = strategies.DefaultGitHubAPIBase
	mintStore         = func(cfg config.Config) connections.Store {
		return newDispatchedStore(cfg, llmcontext.DefaultLookup)
	}
	mintAuditEmitter = func() (audit.Emitter, func(), error) {
		l, cleanup, err := requireAuditLogger("mint")
		if err != nil {
			return nil, nil, err
		}
		return audit.AsEmitter(l), cleanup, nil
	}
	mintPolicyConfig = operatorConfig
	mintLookup       = llmcontext.DefaultLookup
)

// mintResult is the --format json reply. Its four fields are a stable
// contract for scripts.
type mintResult struct {
	Token       string            `json:"token"`
	ExpiresAt   string            `json:"expires_at"`
	Repository  string            `json:"repository"`
	Permissions map[string]string `json:"permissions"`
}

type mintOptions struct {
	connection  string
	namespace   string
	repo        string
	permissions []string
	format      string
}

func newMintCmd() *cobra.Command {
	var opts mintOptions
	cmd := &cobra.Command{
		Use:   "mint <connection> --repo <owner/name> --permission <name>=<level> ... --format json",
		Short: "Mint a short-lived token scoped to one repository",
		Long: `mint issues a GitHub App installation token for exactly one repository
and the listed permissions. The App's JWT is signed inside Keylatch; the
private key never leaves it.

The connection's mint.github_app policy in the operator's config.json is
checked before the key is read: caller kind (service and host by default;
agent sessions never), owner deny list, owner and repository allowlists,
permission ceiling and max_ttl. GitHub's reply must match the request
exactly, or the token is revoked and mint fails. Each mint writes one
audit line without the token.

Output (--format json): {"token","expires_at","repository","permissions"}.

Exit codes: 0 minted; 1 usage error; 2 refused for an agent session or a
missing audit log; 3 refused by policy; 4 store unavailable; 5 GitHub
refused, the reply did not match (token revoked) or auditing failed
(token revoked); 6 connection field missing (private_key, app_id or
installation_<owner>).

Example:
  keylatch mint github-app --repo octo/app --permission contents=write \
    --permission metadata=read --format json`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			opts.connection = args[0]
			return runMint(c, opts)
		},
	}
	cmd.Flags().StringVar(&opts.repo, "repo", "", "repository the token is limited to, as owner/name (required)")
	cmd.Flags().StringArrayVar(&opts.permissions, "permission", nil, "permission to grant, as name=read|write|admin (repeatable, at least one)")
	cmd.Flags().StringVar(&opts.format, "format", "json", "output format: json")
	cmd.Flags().StringVar(&opts.namespace, "namespace", "default", "vault namespace of the connection")
	_ = cmd.MarkFlagRequired("repo")
	return cmd
}

func newMintFailed(format string, args ...any) *CLIError {
	return &CLIError{Class: "MintFailed", Code: exitcode.OperationFailed, Message: fmt.Sprintf(format, args...)}
}

func runMint(c *cobra.Command, opts mintOptions) error {
	ctx := c.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	req, err := parseMintRequest(opts)
	if err != nil {
		return err
	}
	tmpl, err := registry.Get(opts.connection)
	if err != nil || !slices.ContainsFunc(tmpl.Capabilities, func(cp registry.Capability) bool { return cp.Name == mintCapability }) {
		return NewUsageError("mint: %q is not a connection type that can mint (use a github-app connection)", opts.connection)
	}

	caller := mintCallerKind(mintLookup)
	if caller == mint.CallerAgent {
		return NewSecurityBlock("mint: agent sessions cannot mint credentials; detected via: %s",
			strings.Join(llmcontext.Reasons(mintLookup), ", "))
	}
	cfg, err := mintPolicyConfig()
	if err != nil {
		return NewPolicyDeny("mint: the mint policy cannot be read: %v", err)
	}
	policy := githubAppMintPolicy(cfg, opts.connection)
	if err := mint.CheckGitHubApp(policy, caller, req); err != nil {
		return NewPolicyDeny("mint: %v", err)
	}

	emitter, cleanup, err := mintAuditEmitter()
	if err != nil {
		return err
	}
	defer cleanup()
	if err := audit.Ready(emitter); err != nil {
		return NewSecurityBlock("mint: the audit log is not available (%v); Keylatch does not mint unaudited credentials", err)
	}

	strategy, err := loadGitHubAppStrategy(ctx, c, opts, tmpl.Category, req.Repository)
	if err != nil {
		return err
	}

	tok, err := strategy.MintScoped(ctx, strategies.GitHubAppScope{Repository: req.Repository, Permissions: req.Permissions}, mint.MaxLifetime(policy))
	if err != nil {
		reason := "github_error"
		if errors.Is(err, strategies.ErrScopeMismatch) {
			reason = "scope_mismatch"
		}
		_ = emitMintEvent(ctx, emitter, opts, caller, req, time.Time{}, audit.OutcomeError, reason)
		return newMintFailed("mint: %v", err)
	}
	defer tok.Zero()

	if err := emitMintEvent(ctx, emitter, opts, caller, req, tok.ExpiresAt, audit.OutcomeOK, ""); err != nil {
		if rerr := strategy.Revoke(ctx, tok.Token); rerr != nil {
			return newMintFailed("mint: the audit line could not be written (%v) and revoking the token failed: %v", err, rerr)
		}
		return newMintFailed("mint: the audit line could not be written (%v); the token was revoked", err)
	}

	out, err := json.Marshal(mintResult{
		Token:       string(tok.Token),
		ExpiresAt:   tok.ExpiresAt.UTC().Format(time.RFC3339),
		Repository:  req.Repository,
		Permissions: tok.Permissions,
	})
	if err != nil {
		return newMintFailed("mint: encode result: %v", err)
	}
	defer clear(out)
	if _, err := c.OutOrStdout().Write(append(out, '\n')); err != nil {
		return newMintFailed("mint: write result: %v", err)
	}
	return nil
}

func parseMintRequest(opts mintOptions) (mint.Request, error) {
	if opts.format != "json" {
		return mint.Request{}, NewUsageError("mint: --format %q is not supported; use --format json", opts.format)
	}
	if _, _, err := mint.ParseRepository(opts.repo); err != nil {
		return mint.Request{}, NewUsageError("mint: --repo: %v", err)
	}
	if len(opts.permissions) == 0 {
		return mint.Request{}, NewUsageError("mint: at least one --permission name=level is required")
	}
	perms := make(map[string]string, len(opts.permissions))
	for _, p := range opts.permissions {
		k, v, err := mint.ParsePermission(p)
		if err != nil {
			return mint.Request{}, NewUsageError("mint: --permission: %v", err)
		}
		if _, dup := perms[k]; dup {
			return mint.Request{}, NewUsageError("mint: --permission %s given more than once", k)
		}
		perms[k] = v
	}
	return mint.Request{Repository: opts.repo, Permissions: perms}, nil
}

// mintCallerKind classifies the caller. An agent session is checked first
// and wins; systemd sets INVOCATION_ID for service units. These signals can
// be hidden by an agent, which then counts as host: the policy's repository
// allowlist and permission ceiling bound what such a caller can mint.
func mintCallerKind(env llmcontext.Lookup) mint.CallerKind {
	switch {
	case llmcontext.IsLLMSession(env):
		return mint.CallerAgent
	case env("INVOCATION_ID") != "":
		return mint.CallerService
	case interactiveStdin():
		return mint.CallerHuman
	default:
		return mint.CallerHost
	}
}

func githubAppMintPolicy(cfg config.Config, connection string) *config.GitHubAppMintPolicy {
	cp, ok := cfg.Connections[connection]
	if !ok || cp.Mint == nil {
		return nil
	}
	return cp.Mint.GitHubApp
}

// operatorConfig reads the operator's default config file only: the
// KEYLATCH_CONFIG and directory overrides are caller-controlled and must not
// widen what can be minted. A missing file yields an empty config.
func operatorConfig() (config.Config, error) {
	home, err := operatorHome()
	if err != nil {
		return config.Config{}, err
	}
	path := paths.DefaultConfig(home)
	data, err := readOperatorFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return config.Config{}, nil
	}
	if err != nil {
		return config.Config{}, err
	}
	return config.LoadBytes(path, data)
}

func loadGitHubAppStrategy(ctx context.Context, c *cobra.Command, opts mintOptions, category, repo string) (*strategies.GitHubAppInstallationStrategy, error) {
	store := mintStore(loadCLIConfig(c))
	owner, _, _ := strings.Cut(repo, "/")
	read := func(path, field string) ([]byte, error) {
		v, _, err := store.Get(ctx, path)
		if errors.Is(err, backend.ErrNotFound) || (err == nil && len(v) == 0) {
			return nil, NewSecretNotFound("mint: connection %s (namespace %s) has no %s; add it with keylatch connect", opts.connection, opts.namespace, field)
		}
		if err != nil {
			return nil, NewBackendUnavailable("mint: read %s: %v", field, err)
		}
		return v, nil
	}

	instField := "installation_" + strings.ToLower(owner)
	inst, err := read(connections.ConfigFieldPath(opts.namespace, category, opts.connection, instField), instField)
	if err != nil {
		return nil, err
	}
	appID, err := read(connections.ConfigFieldPath(opts.namespace, category, opts.connection, "app_id"), "app_id")
	if err != nil {
		return nil, err
	}
	keyPEM, err := read(connections.SecretFieldPath(opts.namespace, category, opts.connection, "private_key"), "private_key")
	if err != nil {
		return nil, err
	}
	key, err := strategies.ParseGitHubAppPrivateKey(keyPEM)
	clear(keyPEM)
	if err != nil {
		return nil, newMintFailed("mint: %v", err)
	}
	return strategies.NewGitHubAppInstallationStrategy(
		strings.TrimSpace(string(appID)), strings.TrimSpace(string(inst)), key,
		strategies.WithGitHubAPIBase(mintGitHubAPIBase),
	), nil
}

func emitMintEvent(ctx context.Context, em audit.Emitter, opts mintOptions, caller mint.CallerKind, req mint.Request, expiresAt time.Time, outcome audit.Outcome, reason string) error {
	extra := map[string]any{
		"connection":  opts.connection,
		"namespace":   opts.namespace,
		"repository":  req.Repository,
		"permissions": formatPermissions(req.Permissions),
		"caller_kind": string(caller),
	}
	if !expiresAt.IsZero() {
		extra["expires_at"] = expiresAt.UTC().Format(time.RFC3339)
	}
	if reason != "" {
		extra["reason"] = reason
	}
	return em.Emit(ctx, audit.Event{
		Timestamp:   time.Now().UTC(),
		Action:      audit.ActionMint,
		Outcome:     outcome,
		RuntimeMode: "cli",
		Extra:       extra,
	})
}

func formatPermissions(p map[string]string) string {
	keys := slices.Sorted(maps.Keys(p))
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + p[k]
	}
	return strings.Join(parts, ",")
}
