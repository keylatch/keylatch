package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/ci"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/policy/enforce"
)

// Replaced in tests.
var (
	ciVerifier = &ci.Verifier{}
	ciGetenv   = os.Getenv
	ciNow      = time.Now
)

const gitlabTokenEnv = "KEYLATCH_CI_ID_TOKEN"

type ciExchangeOptions struct {
	provider, audience, tokenEnv, envFile string
}

func newCICmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ci",
		Short: "Use Keylatch from a CI job without stored credentials",
	}
	cmd.AddCommand(newCIExchangeCmd())
	return cmd
}

func newCIExchangeCmd() *cobra.Command {
	var opts ciExchangeOptions
	cmd := &cobra.Command{
		Use:   "exchange --provider github-actions|gitlab [--audience <a>]",
		Short: "Verify the job's OIDC token and scope later keylatch commands to the trusted connections",
		Long: `exchange verifies the OIDC token the CI provider issued to this job against
the ci.trust entries in the operator's config.json: issuer, audience,
repository, ref (branch and tag are different refs), environment and
job_workflow_ref. When an entry accepts the token it writes a session record
that lists only that entry's connections and exports KEYLATCH_CI_SESSION to
the file the CI system reads between steps (GITHUB_ENV on GitHub Actions,
--env-file elsewhere). Later keylatch commands in the job refuse every other
connection and stop at the session's expiry.

The token is never printed. One JSON line per exchange, without values, goes
to standard error, which is the job log.

GitHub Actions: the job needs "permissions: id-token: write". GitLab: define
an id_token with the audience and expose it as KEYLATCH_CI_ID_TOKEN (or name
another variable with --token-env).

Backend credentials come from the CI system's own identity federation (AWS
AssumeRoleWithWebIdentity, GCP workload identity federation, Azure federated
credentials) or from a machine account in the CI secret store, as configured
for the backend; exchange does not hold them.

Exit codes: 0 accepted; 1 usage error; 3 no trust entry accepts the token;
4 the issuer's keys could not be fetched (fails closed).

Example:
  keylatch ci exchange --provider github-actions --audience keylatch-ci`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error { return runCIExchange(c, opts) },
	}
	cmd.Flags().StringVar(&opts.provider, "provider", "", "CI provider: github-actions or gitlab (required)")
	cmd.Flags().StringVar(&opts.audience, "audience", "", "audience the job's token carries; defaults to the only trust entry's")
	cmd.Flags().StringVar(&opts.tokenEnv, "token-env", gitlabTokenEnv, "variable holding the job's ID token (gitlab)")
	cmd.Flags().StringVar(&opts.envFile, "env-file", "", "file to append KEYLATCH_CI_SESSION to; GITHUB_ENV on GitHub Actions")
	_ = cmd.MarkFlagRequired("provider")
	return cmd
}

type ciLogLine struct {
	Event       string   `json:"event"`
	Outcome     string   `json:"outcome"`
	Provider    string   `json:"provider"`
	Repository  string   `json:"repository,omitempty"`
	Ref         string   `json:"ref,omitempty"`
	Environment string   `json:"environment,omitempty"`
	Connections []string `json:"connections,omitempty"`
	Expires     string   `json:"expires,omitempty"`
	Reason      string   `json:"reason,omitempty"`
}

func runCIExchange(c *cobra.Command, opts ciExchangeOptions) error {
	if opts.provider != ci.GitHubActions && opts.provider != ci.GitLab {
		return NewUsageError("ci exchange: --provider must be %s or %s", ci.GitHubActions, ci.GitLab)
	}
	cfg, err := config.Load(paths.Config(llmcontext.DefaultLookup))
	if err != nil {
		return NewPolicyDeny("ci exchange: the trust configuration cannot be read: %v", err)
	}
	var trust []config.CITrust
	if cfg.CI != nil {
		trust = cfg.CI.Trust
	}
	audience, err := ciAudience(trust, opts)
	if err != nil {
		return err
	}
	line := ciLogLine{Event: "ci.exchange", Provider: opts.provider}
	deny := func(reason string, err error) error {
		line.Outcome, line.Reason = "denied", reason
		emitCILine(c, line)
		return NewPolicyDeny("ci exchange: %v", err)
	}

	ctx := c.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	raw, err := ciToken(ctx, opts, audience)
	if err != nil {
		return deny("no_token", err)
	}
	entry, id, err := ciVerifier.VerifyAny(ctx, raw, trust, opts.provider, audience)
	if err != nil {
		if errors.Is(err, ci.ErrKeys) {
			line.Outcome, line.Reason = "error", "keys_unavailable"
			emitCILine(c, line)
			return NewBackendUnavailable("ci exchange: %v", err)
		}
		return deny(ciReason(err), err)
	}

	session := ci.NewSession(id, entry, ciNow())
	path, err := ci.WriteSession(ci.SessionDir(ciGetenv), session)
	if err != nil {
		return NewInternalError("ci exchange: write the session record: %v", err)
	}
	if file := firstNonEmpty(opts.envFile, ciGetenv("GITHUB_ENV")); file != "" {
		if err := ci.ExportEnv(file, ci.SessionEnv, path); err != nil {
			return NewInternalError("ci exchange: export %s: %v", ci.SessionEnv, err)
		}
	}
	line.Outcome, line.Repository, line.Ref, line.Environment = "ok", id.Repository, id.Ref, id.Environment
	line.Connections, line.Expires = session.Connections, session.Expires.Format(time.RFC3339)
	emitCILine(c, line)
	_, _ = fmt.Fprintf(c.OutOrStdout(), "session: %s\nconnections: %s\nexpires: %s\n", path, strings.Join(session.Connections, ", "), line.Expires)
	return nil
}

func ciAudience(trust []config.CITrust, opts ciExchangeOptions) (string, error) {
	if opts.audience != "" {
		return opts.audience, nil
	}
	var found []string
	for _, t := range trust {
		if t.Provider == opts.provider && t.Audience != "" {
			found = append(found, t.Audience)
		}
	}
	if len(found) == 0 {
		return "", NewPolicyDeny("ci exchange: config.json has no ci.trust entry for %s", opts.provider)
	}
	for _, a := range found[1:] {
		if a != found[0] {
			return "", NewUsageError("ci exchange: several audiences are trusted for %s; name one with --audience", opts.provider)
		}
	}
	return found[0], nil
}

func ciToken(ctx context.Context, opts ciExchangeOptions, audience string) (string, error) {
	if opts.provider == ci.GitHubActions {
		return ci.GitHubToken(ctx, nil, ciGetenv, audience)
	}
	if tok := ciGetenv(opts.tokenEnv); tok != "" {
		return tok, nil
	}
	return "", fmt.Errorf("%s is empty; define an id_token for the job and expose it under that name", opts.tokenEnv)
}

func ciReason(err error) string {
	switch {
	case errors.Is(err, ci.ErrRepository):
		return "repository_not_trusted"
	case errors.Is(err, ci.ErrRef):
		return "ref_not_trusted"
	case errors.Is(err, ci.ErrEnvironment):
		return "environment_not_trusted"
	case errors.Is(err, ci.ErrWorkflow):
		return "workflow_not_trusted"
	case errors.Is(err, ci.ErrTrustInvalid):
		return "trust_invalid"
	case errors.Is(err, ci.ErrToken):
		return "token_invalid"
	}
	return "no_trust_match"
}

func emitCILine(c *cobra.Command, l ciLogLine) {
	if b, err := json.Marshal(l); err == nil {
		_, _ = fmt.Fprintln(c.ErrOrStderr(), string(b))
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ciScopedEnforce narrows next to the connections of the CI session the job
// exchanged for. With no session variable it changes nothing; with one that
// is unreadable, damaged or expired it denies every request, because the job
// meant to be scoped.
func ciScopedEnforce(next func(context.Context, enforce.Request) enforce.Decision) func(context.Context, enforce.Request) enforce.Decision {
	return func(ctx context.Context, req enforce.Request) enforce.Decision {
		path := ciGetenv(ci.SessionEnv)
		if path == "" {
			return next(ctx, req)
		}
		session, err := ci.ReadSession(path)
		if err != nil {
			return enforce.Decision{Reason: "the CI session record cannot be used: " + err.Error(), Source: "ci-session", SafeFix: "run keylatch ci exchange again"}
		}
		if !session.Allows(req.Connection, ciNow()) {
			return enforce.Decision{Reason: "the CI session does not cover connection " + req.Connection + " (or has expired)", Source: "ci-session", SafeFix: "list the connection in the ci.trust entry, or run keylatch ci exchange again"}
		}
		return next(ctx, req)
	}
}
