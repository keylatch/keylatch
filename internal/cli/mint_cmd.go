package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/broker/strategies"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/mintsession"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/policy/mint"
	"github.com/keylatch/keylatch/internal/providermint"
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
	scopes      []string
	format      string
}

func newMintCmd() *cobra.Command {
	var opts mintOptions
	cmd := &cobra.Command{
		Use:   "mint <connection> --scope <key>=<value> ... --format json",
		Short: "Mint a short-lived, scoped credential",
		Long: `mint issues a short-lived credential limited to the scope you name. The
provider's root credential is read inside Keylatch and never leaves it.

The connection's mint policy in the operator's config.json is checked before
anything is read: caller kind (service and host by default; agent sessions
never), what the policy allows, and max_ttl. The provider's reply must match
the request, or nothing is returned. Each mint writes one audit line without
the credential.

Scope keys (--scope key=value, repeatable where noted):
  github-app   repo=<owner/name>, and <permission>=read|write|admin for each
               permission (--repo and --permission are the same thing)
  aws          role_arn=<IAM role ARN>, duration=<seconds>; the policy's role
               and session policy, with 900 seconds up to its max_ttl
  gcp          scope=<oauth scope>, repeatable; at most the policy's scopes
  azure        resource=<application ID URI>; the policy's resource
  oauth-refresh scope=<scope>, repeatable; at most the policy's scopes
  hashicorp-vault path=<dynamic-secret path>; the policy's path

Output (--format json): GitHub App {"token","expires_at","repository",
"permissions"}. Other providers {"expires_at","scope"} with "token" for an
access token, "data" for AWS credentials, or "data" and "lease_id" for a Vault secret. A Vault lease is
not revoked here, because the credential is handed to you; it ends by itself
within an hour. keylatch run --runtime minted revokes it when the command
exits.

AWS sessions cannot be revoked by Keylatch and expire at the granted time.
Use keylatch run --runtime minted to expose an AWS credential endpoint to a command.

Exit codes: 0 minted; 1 usage error; 2 refused for an agent session or a
missing audit log; 3 refused by policy; 4 store unavailable; 5 the provider
refused, the reply did not match (nothing returned; a GitHub token or Vault
lease is revoked) or auditing failed; 6 connection field missing.

Example:
  keylatch mint github-app --scope repo=octo/app --scope contents=write \
    --scope metadata=read --format json`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			opts.connection = args[0]
			return runMint(c, opts)
		},
	}
	cmd.Flags().StringArrayVar(&opts.scopes, "scope", nil, "what the credential is limited to, as key=value (repeatable); see the keys per provider above")
	cmd.Flags().StringVar(&opts.repo, "repo", "", "GitHub App: repository the token is limited to, as owner/name (same as --scope repo=)")
	cmd.Flags().StringArrayVar(&opts.permissions, "permission", nil, "GitHub App: permission to grant, as name=read|write|admin (same as --scope name=level)")
	cmd.Flags().StringVar(&opts.format, "format", "json", "output format: json")
	cmd.Flags().StringVar(&opts.namespace, "namespace", "default", "vault namespace of the connection")
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

	tmpl, tmplErr := registry.Get(opts.connection)
	if tmplErr == nil && providermint.Supports(tmpl.Provider) {
		return runProviderMint(ctx, c, opts, tmpl)
	}
	if err := applyGitHubScopes(&opts); err != nil {
		return err
	}
	req, err := parseMintRequest(opts)
	if err != nil {
		return err
	}
	if tmplErr != nil || !slices.ContainsFunc(tmpl.Capabilities, func(cp registry.Capability) bool { return cp.Name == mintCapability }) {
		return NewUsageError("mint: %q is not a connection type that can mint (use a github-app, aws, gcp, azure, oauth-refresh or hashicorp-vault connection)", opts.connection)
	}
	if tmpl.Provider != "github-app" {
		return NewUsageError("mint: %q has no mint scope; it is minted for one command with keylatch run --runtime minted", opts.connection)
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

// mintCallerKind classifies the caller with the same rules the daemon applies
// to socket peers.
func mintCallerKind(env llmcontext.Lookup) mint.CallerKind {
	return callerkind.Local(env, interactiveStdin()).Kind
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
	strategy, err := mintsession.LoadGitHubApp(ctx, mintStore(loadCLIConfig(c)), opts.namespace, category, opts.connection, repo, mintGitHubAPIBase)
	var field *mintsession.FieldError
	switch {
	case errors.As(err, &field) && field.Missing:
		return nil, NewSecretNotFound("mint: connection %s (namespace %s) has no %s; add it with keylatch connect", opts.connection, opts.namespace, field.Field)
	case errors.As(err, &field):
		return nil, NewBackendUnavailable("mint: read %s: %v", field.Field, field.Err)
	case err != nil:
		return nil, newMintFailed("mint: %v", err)
	}
	return strategy, nil
}

func emitMintEvent(ctx context.Context, em audit.Emitter, opts mintOptions, caller mint.CallerKind, req mint.Request, expiresAt time.Time, outcome audit.Outcome, reason string) error {
	return mintsession.AuditEvent{
		Connection: opts.connection, Namespace: opts.namespace, Repository: req.Repository, Permissions: req.Permissions,
		Caller: caller, RuntimeMode: "cli", ExpiresAt: expiresAt, Outcome: outcome, Reason: reason,
	}.Emit(ctx, em)
}
