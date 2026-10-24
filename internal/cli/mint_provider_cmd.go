package cli

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/mintsession"
	"github.com/keylatch/keylatch/internal/policy/mint"
	"github.com/keylatch/keylatch/internal/providermint"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/spf13/cobra"
)

// providerMintResult is the --format json reply for providers other than
// GitHub. Token is set for an access token; Data and LeaseID for a Vault secret.
type providerMintResult struct {
	Token     string              `json:"token,omitempty"`
	Data      map[string]string   `json:"data,omitempty"`
	LeaseID   string              `json:"lease_id,omitempty"`
	ExpiresAt string              `json:"expires_at"`
	Scope     map[string][]string `json:"scope"`
}

// applyGitHubScopes folds --scope repo=owner/name and --scope <permission>=<level>
// into the GitHub App's own flags.
func applyGitHubScopes(opts *mintOptions) error {
	for _, s := range opts.scopes {
		k, v, ok := strings.Cut(s, "=")
		if !ok || k == "" || v == "" {
			return NewUsageError("mint: --scope %q must be key=value", s)
		}
		if k == "repo" {
			if opts.repo != "" && opts.repo != v {
				return NewUsageError("mint: the repository is given twice (--repo and --scope repo=)")
			}
			opts.repo = v
			continue
		}
		opts.permissions = append(opts.permissions, s)
	}
	return nil
}

func runProviderMint(ctx context.Context, c *cobra.Command, opts mintOptions, tmpl registry.ConnectionTemplate) error {
	if opts.format != "json" {
		return NewUsageError("mint: --format %q is not supported; use --format json", opts.format)
	}
	if opts.repo != "" || len(opts.permissions) > 0 {
		return NewUsageError("mint: --repo and --permission are for GitHub App connections; use --scope %s=<value>", strings.Join(providermint.ScopeKeys(tmpl.Provider), "|"))
	}
	scope, err := providermint.ParseScope(tmpl.Provider, opts.scopes)
	if err != nil {
		return NewUsageError("mint: %v", err)
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
	emitter, cleanup, err := mintAuditEmitter()
	if err != nil {
		return err
	}
	defer cleanup()
	if err := audit.Ready(emitter); err != nil {
		return NewSecurityBlock("mint: the audit log is not available (%v); Keylatch does not mint unaudited credentials", err)
	}

	secret, err := providermint.Mint(ctx, providermint.Request{
		Store: mintStore(loadCLIConfig(c)), Template: tmpl, Config: cfg, Connection: opts.connection, Namespace: opts.namespace,
		Caller: caller, Scope: scope, Audit: emitter, RuntimeMode: "cli", Endpoints: mintEndpoints,
	})
	if err != nil {
		return providerMintError(opts, err)
	}
	// The credential goes to the caller, so the lease cannot be revoked first.
	defer secret.Release()

	res := providerMintResult{ExpiresAt: secret.ExpiresAt.UTC().Format(time.RFC3339), Scope: secret.Scope, LeaseID: secret.LeaseID}
	if tok, ok := secret.Value("access_token"); ok {
		res.Token = string(tok)
		clear(tok)
	} else {
		res.Data = map[string]string{}
		for f := range maps.Keys(secret.Fields) {
			v, _ := secret.Value(f)
			res.Data[f] = string(v)
			clear(v)
		}
	}
	out, err := json.Marshal(res)
	if err != nil {
		return newMintFailed("mint: encode result: %v", err)
	}
	defer clear(out)
	if _, err := c.OutOrStdout().Write(append(out, '\n')); err != nil {
		return newMintFailed("mint: write result: %v", err)
	}
	return nil
}

func providerMintError(opts mintOptions, err error) error {
	var field *mintsession.FieldError
	switch {
	case errors.Is(err, mint.ErrDenied), errors.Is(err, mint.ErrInvalidProviderPolicy), errors.Is(err, mint.ErrInvalidAWSPolicy):
		return NewPolicyDeny("mint: %v", err)
	case errors.Is(err, providermint.ErrUsage):
		return NewUsageError("mint: %v", err)
	case errors.As(err, &field) && field.Missing:
		return NewSecretNotFound("mint: connection %s (namespace %s) has no %s; add it with keylatch connect", opts.connection, opts.namespace, field.Field)
	case errors.As(err, &field):
		return NewBackendUnavailable("mint: read %s: %v", field.Field, field.Err)
	}
	return newMintFailed("mint: %v", err)
}
