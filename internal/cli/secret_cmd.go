package cli

import (
	"encoding/json"
	"errors"
	"fmt"
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
https://<first host>/<path>. Restart the gateway after adding or removing one.

See docs/custom-secrets.md.`,
	}
	cmd.AddCommand(newSecretAddCmd(), newSecretListCmd(), newSecretShowCmd(), newSecretRmCmd())
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

// blockSecretMutationInLLMSession refuses commands that write or remove secret
// material in an agent session.
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
			if err := blockSecretMutationInLLMSession("add"); err != nil {
				return err
			}
			if valueStdin && ref != "" || (!replace && !valueStdin && ref == "") {
				return NewUsageError("exactly one of --value-stdin or --ref is required (with --replace, neither keeps the stored value)")
			}
			injection, err := injectionFromFlags(header, query, basic)
			if err != nil {
				return err
			}
			sec := customsecret.Secret{
				Name: args[0], Hosts: hosts, Paths: pathFlags, Methods: methods,
				Injection: injection, BaseURLEnv: baseURLEnv, CreatedAt: time.Now().UTC(),
			}
			if err := sec.Normalize(); err != nil {
				return NewUsageError("%v", err)
			}
			file := paths.CustomSecrets(llmcontext.DefaultLookup)
			existing, findErr := customsecret.Find(file, sec.Name)
			switch {
			case replace && findErr != nil:
				return NewUsageError("custom secret %q does not exist; add it without --replace", sec.Name)
			case !replace && findErr == nil:
				return NewUsageError("custom secret %q already exists; use --replace to change it or remove it with: keylatch secret rm %s", sec.Name, sec.Name)
			case !replace:
				if err := customsecret.Check(sec.Name); err != nil {
					return NewUsageError("%v", err)
				}
			}

			var value []byte
			if replace && ref == "" && !valueStdin {
				sec.RefScheme = existing.RefScheme
			} else if ref != "" {
				scheme, refErr := customsecret.RefSchemeOf(ref)
				if refErr != nil {
					// The cause is not shown: a secret passed by mistake must not reach stderr.
					return NewUsageError("--ref must be an op://, aws-sm:// or hashivault:// reference (secret values are never accepted as arguments)")
				}
				sec.RefScheme = scheme
				value = []byte(strings.TrimSpace(ref))
			} else {
				value, err = readSecretValue(c)
				if err != nil {
					return withExitCode(exitcode.UserError, fmt.Errorf("[keylatch] error: %w", err))
				}
				if err := customsecret.ValidateValue(value); err != nil {
					return NewUsageError("%v", err)
				}
			}
			defer func() {
				for i := range value {
					value[i] = 0
				}
			}()

			// Refuse before storing anything: an unaudited write would not be recorded.
			al, auditCleanup, err := requireAuditLogger("secret add")
			if err != nil {
				return err
			}
			defer auditCleanup()
			ctx := audit.WithEmitter(c.Context(), audit.AsEmitter(al))

			cfg := loadCLIConfig(c)
			env := llmcontext.DefaultLookup
			valuePath := customsecret.ValuePath(sec.Name)
			// The value is written before the rules so a failure never leaves rules without a value.
			if value != nil {
				meta := backend.Meta{Path: valuePath, Backend: cfg.Backend, Version: 1}
				if err := vault.Set(ctx, valuePath, value, meta, cfg, env); err != nil {
					return withExitCode(exitcode.OperationFailed, fmt.Errorf("[keylatch] error: store value: %w", err))
				}
			}
			if replace {
				if err := customsecret.Replace(file, sec); err != nil {
					return withExitCode(exitcode.OperationFailed, fmt.Errorf("[keylatch] error: save rule: %w", err))
				}
				fmt.Fprintf(c.OutOrStdout(), "[keylatch] secret replaced: %s -> %s (%s, %s)\n", sec.Name, sec.Hosts[0], sec.Kind(), sec.Source())
				fmt.Fprintln(c.OutOrStdout(), "  restart the gateway to serve the new rules")
				return nil
			}
			if err := customsecret.Add(file, sec); err != nil {
				if delErr := vault.Delete(ctx, valuePath, cfg, env); delErr != nil && !errors.Is(delErr, backend.ErrNotFound) {
					return withExitCode(exitcode.OperationFailed, fmt.Errorf("[keylatch] error: save rule: %v (stored value could not be removed: %v)", err, delErr))
				}
				return withExitCode(exitcode.OperationFailed, fmt.Errorf("[keylatch] error: save rule: %w", err))
			}
			fmt.Fprintf(c.OutOrStdout(), "[keylatch] secret added: %s -> %s (%s, %s)\n", sec.Name, sec.Hosts[0], sec.Kind(), sec.Source())
			fmt.Fprintf(c.OutOrStdout(), "  gateway path: /sdk/%s/v1/<path>  (restart the gateway to serve it)\n", sec.Name)
			return nil
		},
	}
	cmd.Flags().BoolVar(&valueStdin, "value-stdin", false, "read the secret value from stdin")
	cmd.Flags().StringVar(&ref, "ref", "", "external-store reference (op://..., aws-sm://..., hashivault://...) instead of a value")
	cmd.Flags().StringArrayVar(&hosts, "host", nil, "allowed HTTPS host (repeatable; the first receives requests; *.example.com allowed after it)")
	cmd.Flags().StringArrayVar(&pathFlags, "path", nil, "allowed upstream path prefix (repeatable; default /)")
	cmd.Flags().StringArrayVar(&methods, "method", nil, "allowed HTTP method (repeatable; default any)")
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

// readSecretValue reads the value from a pipe, or prompts without echo on a terminal.
func readSecretValue(c *cobra.Command) ([]byte, error) {
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
			w := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tHOSTS\tINJECTION\tSOURCE")
			for _, s := range secrets {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Name, strings.Join(s.Hosts, ","), s.Kind(), s.Source())
			}
			return w.Flush()
		},
	}
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
			fmt.Fprintf(out, "hosts:       %s\n", strings.Join(s.Hosts, ", "))
			fmt.Fprintf(out, "paths:       %s\n", strings.Join(s.Paths, ", "))
			methods := "any"
			if len(s.Methods) > 0 {
				methods = strings.Join(s.Methods, ", ")
			}
			fmt.Fprintf(out, "methods:     %s\n", methods)
			fmt.Fprintf(out, "injection:   %s\n", s.Kind())
			if s.Injection.Format != "" {
				fmt.Fprintf(out, "format:      %s\n", s.Injection.Format)
			}
			fmt.Fprintf(out, "source:      %s\n", s.Source())
			if s.BaseURLEnv != "" {
				fmt.Fprintf(out, "base url env: %s\n", s.BaseURLEnv)
			}
			fmt.Fprintf(out, "gateway:     /sdk/%s/v1/<path>\n", s.Name)
			fmt.Fprintf(out, "created:     %s\n", s.CreatedAt.Format(time.RFC3339))
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
			if err := vault.Delete(ctx, customsecret.ValuePath(name), loadCLIConfig(c), llmcontext.DefaultLookup); err != nil && !errors.Is(err, backend.ErrNotFound) {
				return withExitCode(exitcode.OperationFailed, fmt.Errorf("[keylatch] error: delete value: %w", err))
			}
			if err := customsecret.Remove(file, name); err != nil {
				return withExitCode(exitcode.OperationFailed, fmt.Errorf("[keylatch] error: %w", err))
			}
			fmt.Fprintf(c.OutOrStdout(), "[keylatch] secret removed: %s\n", name)
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "skip the confirmation prompt")
	return cmd
}
