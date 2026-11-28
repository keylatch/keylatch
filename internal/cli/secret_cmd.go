package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/customsecret"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/vault"
	"github.com/spf13/cobra"
)

// newSecretCmd returns the `secret` group: user-defined secrets for services
// that have no provider template.
func newSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Manage custom secrets for services without a provider template",
		Long: `Custom secrets let the gateway call any HTTPS API with a key you hold, without
a provider template. A secret is a value (or an op://, aws-sm:// or hashivault://
reference), the hosts and paths it may be sent to, and how it is injected.

The gateway serves a custom secret at /sdk/<name>/v1/<path> and forwards it to
https://<first host>/<path>; other listed hosts are reached at
/sdk/<name>/h/<host>/<path>. Restart the gateway after adding or removing one.

See docs/custom-secrets.md.`,
	}
	cmd.AddCommand(newSecretAddCmd(), newSecretListCmd(), newSecretShowCmd(), newSecretRmCmd(), newSecretApproveCmd(), newSecretRejectCmd())
	return cmd
}

// registerCustomSecrets adds the user's custom secrets to the provider registry.
// The metadata file holds no value, so this needs no backend access. A broken
// entry is reported and skipped so it cannot take the other commands down.
func registerCustomSecrets(env llmcontext.Lookup) {
	secrets, err := customsecret.Load(paths.CustomSecrets(env))
	if err != nil {
		slog.Warn("custom secrets not loaded", "error", err)
		return
	}
	for _, e := range customsecret.RegisterAll(secrets) {
		slog.Warn("custom secret skipped", "error", e)
	}
}

// blockSecretMutationInLLMSession refuses commands that remove or approve
// secrets in an agent session; an agent may only propose them with `secret add`.
func blockSecretMutationInLLMSession(command string) error {
	if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
		return NewSecurityBlock("secret %s requires a human terminal. Run outside an LLM session.", command)
	}
	return nil
}

func newSecretAddCmd() *cobra.Command {
	var (
		valueStdin bool
		ref        string
		hosts      []string
		pathFlags  []string
		methods    []string
		header     string
		query      string
		basic      string
		baseURLEnv string
		replace    bool
	)
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a custom secret",
		Long: `Add a secret for a service that has no provider template.

The value is read from stdin (--value-stdin) or is an external-store reference
(--ref); it is never accepted as an argument.

Examples:
  printf '%s' "$KEY" | keylatch secret add acme --value-stdin \
      --host api.acme.example --path /v1 --header "Authorization: Bearer {value}"
  keylatch secret add acme --ref op://Private/acme/key \
      --host api.acme.example --query api_key --base-url-env ACME_BASE_URL`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return runSecretAdd(c, secretAddInput{
				name: args[0], valueStdin: valueStdin, ref: ref, hosts: hosts, paths: pathFlags, methods: methods,
				header: header, query: query, basic: basic, baseURLEnv: baseURLEnv, replace: replace,
			})
		},
	}
	cmd.Flags().BoolVar(&valueStdin, "value-stdin", false, "read the secret value from stdin")
	cmd.Flags().StringVar(&ref, "ref", "", "external-store reference (op://..., aws-sm://..., hashivault://...) instead of a value")
	cmd.Flags().StringArrayVar(&hosts, "host", nil, "allowed upstream HTTPS host, an exact DNS name (repeatable; the first receives /sdk/<name>/v1/ requests)")
	cmd.Flags().StringArrayVar(&pathFlags, "path", nil, "allowed upstream path prefix (repeatable; default /)")
	cmd.Flags().StringArrayVar(&methods, "method", nil, "allowed HTTP method (repeatable; default GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS; TRACE and CONNECT are never allowed)")
	cmd.Flags().StringVar(&header, "header", "", `inject as a header, e.g. "Authorization: Bearer {value}"`)
	cmd.Flags().StringVar(&query, "query", "", "inject as this query parameter")
	cmd.Flags().StringVar(&basic, "basic", "", "inject as HTTP basic auth with this user name")
	cmd.Flags().BoolVar(&replace, "replace", false, "change an existing secret: new rules (all rule flags again) and, with --value-stdin or --ref, a new value")
	cmd.Flags().StringVar(&baseURLEnv, "base-url-env", "", "env var that receives the gateway URL in `keylatch run`")
	return cmd
}

func injectionFromFlags(header, query, basic string) (customsecret.Injection, error) {
	set := 0
	for _, v := range []string{header, query, basic} {
		if v != "" {
			set++
		}
	}
	if set != 1 {
		return customsecret.Injection{}, NewUsageError("exactly one of --header, --query or --basic is required")
	}
	switch {
	case header != "":
		in, err := customsecret.ParseHeaderRule(header)
		if err != nil {
			return in, NewUsageError("%v", err)
		}
		return in, nil
	case query != "":
		return customsecret.Injection{Kind: customsecret.InjectQuery, Name: query}, nil
	}
	return customsecret.Injection{Kind: customsecret.InjectBasic, Name: basic}, nil
}

// readCustomSecretValue reads the value from a pipe, or prompts without echo on a terminal.
func readCustomSecretValue(c *cobra.Command) ([]byte, error) {
	if stdinIsTTY() {
		return promptHidden("Enter secret value")
	}
	return readFieldFromStdin(c.InOrStdin())
}

func newSecretListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List custom secrets (metadata only)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			secrets, err := customsecret.Load(paths.CustomSecrets(llmcontext.DefaultLookup))
			if err != nil {
				return withExitCode(exitcode.OperationFailed, fmt.Errorf("[keylatch] error: %w", err))
			}
			if useJSON, _ := c.Flags().GetBool("json"); useJSON {
				if secrets == nil {
					secrets = []customsecret.Secret{}
				}
				b, _ := json.MarshalIndent(secrets, "", "  ")
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}
			if len(secrets) == 0 {
				fmt.Fprintln(c.OutOrStdout(), "No custom secrets. Add one with: keylatch secret add <name> --help")
				return nil
			}
			printSecretTable(c.OutOrStdout(), secrets)
			return nil
		},
	}
}

// printSecretTable lists secrets by name, state, hosts, injection kind and source.
func printSecretTable(out io.Writer, secrets []customsecret.Secret) {
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSTATE\tHOSTS\tINJECTION\tSOURCE")
	for _, s := range secrets {
		v := s.Shown()
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.Name, s.State(), strings.Join(v.Hosts, ","), v.Kind(), v.Source())
	}
	_ = w.Flush()
}

func printSecretRules(out io.Writer, s customsecret.Secret, indent string) {
	fmt.Fprintf(out, "%shosts:       %s\n", indent, strings.Join(s.Hosts, ", "))
	fmt.Fprintf(out, "%spaths:       %s\n", indent, strings.Join(s.Paths, ", "))
	methods := "any"
	if len(s.Methods) > 0 {
		methods = strings.Join(s.Methods, ", ")
	}
	fmt.Fprintf(out, "%smethods:     %s\n", indent, methods)
	fmt.Fprintf(out, "%sinjection:   %s\n", indent, s.Kind())
	if s.Injection.Format != "" {
		fmt.Fprintf(out, "%sformat:      %s\n", indent, s.Injection.Format)
	}
	if s.BaseURLEnv != "" {
		fmt.Fprintf(out, "%sbase url env: %s\n", indent, s.BaseURLEnv)
	}
}

// gatewayURLs lists the gateway path that reaches each allowed host.
func gatewayURLs(s customsecret.Secret) []string {
	out := make([]string, 0, len(s.Hosts))
	for i, h := range s.Hosts {
		if i == 0 {
			out = append(out, fmt.Sprintf("/sdk/%s/v1/<path>  -> %s (first host, used by --base-url-env)", s.Name, h))
			continue
		}
		out = append(out, fmt.Sprintf("/sdk/%s/h/%s/<path>  -> %s", s.Name, h, h))
	}
	return out
}

func newSecretShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show a custom secret's rules (never the value)",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			s, err := customsecret.Find(paths.CustomSecrets(llmcontext.DefaultLookup), args[0])
			if err != nil {
				return withExitCode(exitcode.UserError, fmt.Errorf("[keylatch] error: %w", err))
			}
			if useJSON, _ := c.Flags().GetBool("json"); useJSON {
				b, _ := json.MarshalIndent(s, "", "  ")
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}
			out := c.OutOrStdout()
			fmt.Fprintf(out, "name:        %s\n", s.Name)
			fmt.Fprintf(out, "state:       %s\n", s.State())
			if s.Active() {
				printSecretRules(out, s, "")
				fmt.Fprintf(out, "source:      %s\n", s.Source())
				fmt.Fprintf(out, "gateway:     %s\n", strings.Join(gatewayURLs(s), "\n             "))
				fmt.Fprintf(out, "created:     %s\n", s.CreatedAt.Format(time.RFC3339))
			}
			if s.Proposed != nil {
				fmt.Fprintln(out, "pending change (not served until approved with: keylatch secret approve "+s.Name+"):")
				printSecretRules(out, *s.Proposed, "  ")
				src := "unchanged"
				if s.NewValue {
					src = s.Proposed.Source() + " (new)"
				}
				fmt.Fprintf(out, "  source:      %s\n", src)
			}
			return nil
		},
	}
}

func newSecretRmCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "rm <name>",
		Short: "Remove a custom secret and its stored value",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := blockSecretMutationInLLMSession("rm"); err != nil {
				return err
			}
			name := args[0]
			file := paths.CustomSecrets(llmcontext.DefaultLookup)
			if _, err := customsecret.Find(file, name); err != nil {
				return withExitCode(exitcode.UserError, fmt.Errorf("[keylatch] error: %w", err))
			}
			if !force && !confirmPrompt(c, fmt.Sprintf("Remove custom secret %s and its stored value? [y/N]: ", name)) {
				return withExitCode(exitcode.UserError, fmt.Errorf("[keylatch] aborted"))
			}
			al, auditCleanup, err := requireAuditLogger("secret rm")
			if err != nil {
				return err
			}
			defer auditCleanup()
			ctx := audit.WithEmitter(c.Context(), audit.AsEmitter(al))

			// The value goes first: if it cannot be deleted the rule stays and rm can be retried.
			cfg := loadCLIConfig(c)
			err = customsecret.WithLock(file, func(tx customsecret.Tx) error {
				for _, p := range []string{customsecret.ValuePath(name), customsecret.PendingPath(name)} {
					if err := vault.Delete(ctx, p, cfg, llmcontext.DefaultLookup); err != nil && !errors.Is(err, backend.ErrNotFound) {
						return withExitCode(exitcode.OperationFailed, fmt.Errorf("[keylatch] error: delete value: %w", err))
					}
				}
				if err := tx.Remove(name); err != nil {
					return withExitCode(exitcode.OperationFailed, fmt.Errorf("[keylatch] error: %w", err))
				}
				return nil
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "[keylatch] secret removed: %s\n", name)
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "skip the confirmation prompt")
	return cmd
}
