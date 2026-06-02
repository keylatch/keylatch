package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/store"
	"github.com/spf13/cobra"
)

// knownProviderPrefixes are well-known API key prefixes from common providers.
// Any value matching one of these prefixes is treated as sensitive regardless of
// whether its field is marked sensitive: true in the provider template.
var knownProviderPrefixes = []string{
	"sk-ant-",  // Anthropic
	"sk-proj-", // OpenAI project keys (must appear before "sk-")
	"sk_live_", // Stripe live-mode secret keys (must appear before "sk-")
	"sk_test_", // Stripe test-mode secret keys (must appear before "sk-")
	"sk-",      // OpenAI and generic (T-12-01)
	"ghp_",     // GitHub personal access tokens
	"ghs_",     // GitHub Actions tokens
	"gho_",     // GitHub OAuth tokens
	"ghr_",     // GitHub refresh tokens
	"xoxb-",    // Slack bot tokens
	"xoxp-",    // Slack user tokens
	"AKID",     // AWS access key prefix (short form)
	"AKIA",     // AWS access key ID (full form)
	"glpat-",   // GitLab personal access tokens
	"dp.st.",   // Doppler service tokens
	"inf_",     // Infisical tokens
	"op_",      // 1Password service accounts
}

// shannonEntropy computes the Shannon entropy (bits per character) of s.
// Values near 0 indicate low-entropy (e.g. "password"), values near 6-7
// indicate high-entropy random data (e.g. "sk-ant-...").
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int, 64)
	for _, r := range s {
		freq[r]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, count := range freq {
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

// looksLikeSensitive returns true when value appears to be a high-value secret.
//
// Triggers:
//  1. Value matches a known provider key prefix (e.g. "sk-ant-", "ghp_", "AKIA").
//  2. Value has Shannon entropy > 4.0 bits/char AND length > 20.
//
// Non-sensitive values (model names, config keys, short strings) return false.
func looksLikeSensitive(value string) bool {
	// Rule 1: known provider key prefix.
	for _, prefix := range knownProviderPrefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}

	// Rule 2: high-entropy heuristic.
	// Threshold 4.0 is chosen to distinguish API keys / random tokens (entropy ≥ 4.1)
	// from human-readable model names and config values (entropy ≤ 3.9).
	if len(value) > 20 && shannonEntropy(value) > 4.0 {
		return true
	}

	return false
}

// newPhase3ConnectCmd returns the Phase 3 `connect` subcommand group.
func newPhase3ConnectCmd() *cobra.Command {
	connectCmd := &cobra.Command{
		Use:   "connect <provider>",
		Short: "Connect a credential provider",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()
			cfg := loadCLIConfig(c)
			store := newDispatchedStore(cfg, llmcontext.DefaultLookup)

			provider := args[0]
			namespace, _ := c.Flags().GetString("namespace")
			account, _ := c.Flags().GetString("account")
			nonInteractive, _ := c.Flags().GetBool("non-interactive")
			fromEnv, _ := c.Flags().GetBool("from-env")
			useJSON, _ := c.Flags().GetBool("json")
			noTest, _ := c.Flags().GetBool("no-test")
			fieldFlags, _ := c.Flags().GetStringArray("field")
			stdinField, _ := c.Flags().GetString("stdin-field")
			providerRefFlags, _ := c.Flags().GetStringArray("provider-ref")

			// Look up the provider template so we can display helpful errors.
			tmpl, tmplErr := registry.Get(provider)
			if tmplErr != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: provider %q not found in registry.\n", provider)
				fmt.Fprintln(c.ErrOrStderr(), "\n  Run 'keylatch registry list' to see available providers.")
				os.Exit(exitcode.UserError)
				return nil
			}

			// Build the fields map from the various input sources.
			fields := map[string][]byte{}

			// Build a fast lookup of sensitive field names from the provider template.
			// S-INV-6: sensitive fields must not be supplied via argv (shell history leak).
			sensitiveFields := map[string]bool{}
			for _, sf := range tmpl.SecretFields {
				if sf.Sensitive {
					sensitiveFields[sf.Name] = true
				}
			}

			// Parse -f name=value flags.
			for _, kv := range fieldFlags {
				parts := strings.SplitN(kv, "=", 2)
				if len(parts) != 2 {
					fmt.Fprintf(c.ErrOrStderr(), "Error: invalid --field format %q; expected name=value\n", kv)
					os.Exit(exitcode.UserError)
					return nil
				}
				key, val := parts[0], parts[1]

				// S-INV-6: hard-block sensitive values passed via argv.
				// @- (stdin) and @prompt (interactive) are safe — only reject plain values.
				// Extended (T-12-01): also block values matching known provider key prefixes or
				// high-entropy heuristic, regardless of template sensitive: true declaration.
				if !strings.HasPrefix(val, "@") && (sensitiveFields[key] || looksLikeSensitive(val)) {
					cliErr := NewInsecureArgv(
						"field %q contains a sensitive value — do not pass secrets in argv (shell history leak)\n"+
							"  audit: [INSECURE-ARGV]\n"+
							"  use:  --field %s=@-        (stdin)\n"+
							"        --field %s=@prompt   (interactive prompt)\n"+
							"        --provider-ref        (provider-managed reference)",
						key, key, key)
					fmt.Fprint(c.ErrOrStderr(), cliErr.Stderr())
					os.Exit(cliErr.Code)
					return nil
				}

				// Support @- to read from stdin, and @prompt for interactive TTY prompt.
				switch val {
				case "@-":
					data, err := readFieldFromStdin(c.InOrStdin())
					if err != nil {
						fmt.Fprintf(c.ErrOrStderr(), "Error: reading stdin for field %q: %v\n", key, err)
						os.Exit(exitcode.UserError)
						return nil
					}
					fields[key] = data
				case "@prompt":
					if !stdinIsTTY() {
						fmt.Fprintf(c.ErrOrStderr(), "Error: field %q requires --field %s=@prompt but stdin is not a TTY. Use --field %s=@- to read from stdin pipe.\n", key, key, key)
						os.Exit(exitcode.UserError)
						return nil
					}
					data, err := promptHidden(fmt.Sprintf("Enter %s", key))
					if err != nil {
						fmt.Fprintf(c.ErrOrStderr(), "Error: prompting for field %q: %v\n", key, err)
						os.Exit(exitcode.UserError)
						return nil
					}
					fields[key] = data
				default:
					fields[key] = []byte(val)
				}
			}

			// --from-env: read from each SecretField.EnvVar.
			if fromEnv {
				for _, sf := range tmpl.SecretFields {
					if sf.EnvVar == "" {
						continue
					}
					if val := llmcontext.DefaultLookup(sf.EnvVar); val != "" {
						fields[sf.Name] = []byte(val)
					}
				}
			}

			// --stdin-field: read the named field from stdin.
			if stdinField != "" {
				data, err := readFieldFromStdin(c.InOrStdin())
				if err != nil {
					fmt.Fprintf(c.ErrOrStderr(), "Error: reading stdin for field %q: %v\n", stdinField, err)
					os.Exit(exitcode.UserError)
					return nil
				}
				fields[stdinField] = data
			}

			// --provider-ref: resolve external store URI for a field.
			// Format: --provider-ref <field>=<uri>
			// Supported URIs: op://vault/item/field, aws-sm://region/secret, hashivault://mount/path#field
			if len(providerRefFlags) > 0 {
				if err := resolveProviderRefs(ctx, providerRefFlags, fields); err != nil {
					fmt.Fprintf(c.ErrOrStderr(), "Error: --provider-ref: %v\n", err)
					os.Exit(exitcode.OperationFailed)
					return nil
				}
			}

			// Interactive prompting when stdin is a TTY and --json is not set.
			tty := stdinIsTTY()
			if !nonInteractive && !useJSON && tty {
				for _, sf := range tmpl.SecretFields {
					if _, alreadySet := fields[sf.Name]; alreadySet {
						continue
					}
					label := sf.Label
					if label == "" {
						label = sf.Name
					}
					value, err := promptHidden(fmt.Sprintf("Enter %s for %s", label, provider))
					if err != nil {
						fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
						os.Exit(exitcode.UserError)
						return nil
					}
					if len(value) == 0 && sf.Required {
						fmt.Fprintf(c.ErrOrStderr(), "Error: field %q is required\n", sf.Name)
						os.Exit(exitcode.UserError)
						return nil
					}
					// T-12-01: even in --interactive mode, warn when a non-sensitive field
					// receives a value that looks like a high-entropy secret.
					if len(value) > 0 && !sf.Sensitive && looksLikeSensitive(string(value)) {
						fmt.Fprintf(c.ErrOrStderr(),
							"warning: field %q looks like a high-entropy secret (entropy heuristic) — "+
								"consider marking it sensitive: true in the provider template\n",
							sf.Name)
					}
					if len(value) > 0 {
						fields[sf.Name] = value
					}
				}
			}

			// Non-interactive with no TTY and no values provided → actionable error.
			if !tty || nonInteractive {
				for _, sf := range tmpl.SecretFields {
					if sf.Required {
						if _, ok := fields[sf.Name]; !ok {
							printConnectActionableError(c, provider, sf, tmpl)
							os.Exit(exitcode.UserError)
							return nil
						}
					}
				}
			}

			conn, err := connections.Connect(ctx, provider, connections.ConnectOptions{
				Namespace:      namespace,
				Account:        account,
				NonInteractive: nonInteractive || !tty,
				Fields:         fields,
			}, store)
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				os.Exit(exitcode.OperationFailed)
				return nil
			}

			// Automatically test the connection after writing (skip if --no-test is set).
			if noTest {
				if useJSON {
					data, _ := json.Marshal(map[string]interface{}{"connection": conn})
					fmt.Fprintln(c.OutOrStdout(), string(data))
					return nil
				}
				fmt.Fprintf(c.OutOrStdout(), "v %s — stored (connection test skipped)\n", provider)
				return nil
			}
			start := time.Now()
			testResult, testErr := connections.Test(ctx, provider, conn.Account, conn.Namespace, store, nil)
			elapsed := time.Since(start)

			// Check failure FIRST, before formatting output.
			testFailed := testErr != nil || testResult.Status != connections.TestStatusConnected

			if testFailed {
				// Rollback regardless of output format.
				rollbackErr := connections.Delete(ctx, provider, conn.Account, conn.Namespace, store)

				if useJSON {
					rollbackOK := rollbackErr == nil
					data, _ := json.Marshal(map[string]interface{}{
						"connection":  conn,
						"test_result": testResult,
						"rollback_ok": rollbackOK,
					})
					fmt.Fprintln(c.OutOrStdout(), string(data))
					os.Exit(exitcode.OperationFailed)
					return nil
				}

				reason := string(testResult.Status)
				if reason == "" && testErr != nil {
					reason = testErr.Error()
				}
				if reason == "" {
					reason = "unknown error"
				}
				if rollbackErr != nil {
					fmt.Fprintf(c.ErrOrStderr(), "x %s — credential stored but rollback failed: %v\n", provider, rollbackErr)
				} else {
					fmt.Fprintf(c.ErrOrStderr(), "x %s — connection test failed; credential rolled back\n", provider)
				}
				fmt.Fprintf(c.ErrOrStderr(), "  Reason: %s\n", reason)
				docsURL := tmpl.DocsURL
				if docsURL != "" {
					fmt.Fprintf(c.ErrOrStderr(), "  Check your API key at: %s\n", docsURL)
				}
				fmt.Fprintln(c.ErrOrStderr(), "  Re-run 'keylatch connect "+provider+"' once you have a valid key.")
				os.Exit(exitcode.OperationFailed)
				return nil
			}

			// Success path — only reached when test passed.
			if useJSON {
				data, _ := json.Marshal(map[string]interface{}{
					"connection":  conn,
					"test_result": testResult,
				})
				fmt.Fprintln(c.OutOrStdout(), string(data))
				return nil
			}
			fmt.Fprintf(c.OutOrStdout(), "v %s — connection verified (%s)\n", provider, elapsed.Round(time.Millisecond))

			return nil
		},
	}
	connectCmd.Flags().String("namespace", "default", "vault namespace")
	connectCmd.Flags().String("account", "", "account name (multi-account providers)")
	connectCmd.Flags().Bool("non-interactive", false, "skip interactive prompts; fail if required fields are missing")
	connectCmd.Flags().Bool("no-test", false, "store credential without running a connection test (useful for CI/smoke tests)")
	connectCmd.Flags().String("mode", "", "runtime mode override")
	connectCmd.Flags().Bool("from-env", false, "read secret fields from environment variables (uses SecretField.EnvVar)")
	connectCmd.Flags().StringArrayP("field", "f", nil, "supply a field value: -f name=value (repeatable; use @- for stdin)")
	connectCmd.Flags().String("stdin-field", "", "read this named field from stdin")
	connectCmd.Flags().Bool("json", false, "output as JSON")
	connectCmd.Flags().StringArray("provider-ref", nil,
		"resolve a field from an external store URI: --provider-ref field=op://vault/item/field\n"+
			"  Supported: op://vault/item/field  aws-sm://region/secret[#key]  hashivault://mount/path[#field]")

	// Subcommand: connect custom — interactive flow for non-registry providers.
	customCmd := &cobra.Command{
		Use:   "custom",
		Short: "Connect a custom credential provider",
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()
			cfg := loadCLIConfig(c)
			st := newDispatchedStore(cfg, llmcontext.DefaultLookup)

			// Prompt for provider name.
			fmt.Fprintf(c.OutOrStdout(), "  Custom provider name (e.g. my-service): ")
			name := strings.TrimSpace(readLine())
			if name == "" {
				fmt.Fprintln(c.ErrOrStderr(), "Error: provider name is required")
				os.Exit(exitcode.UserError)
				return nil
			}

			// Prompt for field name (default: api_key).
			fmt.Fprintf(c.OutOrStdout(), "  Field name [api_key]: ")
			field := strings.TrimSpace(readLine())
			if field == "" {
				field = "api_key"
			}

			// Prompt hidden value.
			value, err := promptHidden(fmt.Sprintf("Enter value for %s", field))
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				os.Exit(exitcode.UserError)
				return nil
			}

			path := fmt.Sprintf("default/custom/%s/%s", name, field)
			meta := backend.Meta{
				Path:    path,
				Backend: cfg.Backend,
				Version: 1,
			}
			if setErr := st.Set(ctx, path, value, meta); setErr != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", setErr)
				os.Exit(exitcode.OperationFailed)
				return nil
			}

			fmt.Fprintf(c.OutOrStdout(), "  Connected: custom/%s (%s saved)\n", name, field)
			return nil
		},
	}
	connectCmd.AddCommand(customCmd)

	return connectCmd
}

// printConnectActionableError prints an actionable error when required fields are missing
// and the session is non-interactive.
func printConnectActionableError(c *cobra.Command, provider string, sf registry.SecretField, tmpl registry.ConnectionTemplate) {
	label := sf.Label
	if label == "" {
		label = sf.Name
	}
	fmt.Fprintf(c.ErrOrStderr(), "Error: %s requires a %q field.\n\n", provider, label)
	fmt.Fprintln(c.ErrOrStderr(), "  Interactive:")
	fmt.Fprintf(c.ErrOrStderr(), "    keylatch connect %s\n", provider)
	fmt.Fprintln(c.ErrOrStderr(), "    (you'll be prompted for the value)")
	fmt.Fprintln(c.ErrOrStderr())
	if sf.EnvVar != "" {
		fmt.Fprintln(c.ErrOrStderr(), "  From an env var:")
		fmt.Fprintf(c.ErrOrStderr(), "    %s=<value> keylatch connect %s --from-env\n", sf.EnvVar, provider)
		fmt.Fprintln(c.ErrOrStderr())
	}
	fmt.Fprintln(c.ErrOrStderr(), "  From stdin (CI):")
	fmt.Fprintf(c.ErrOrStderr(), "    printf '%%s' \"$KEY\" | keylatch connect %s -f %s=@-\n", provider, sf.Name)
	if tmpl.DocsURL != "" {
		fmt.Fprintln(c.ErrOrStderr())
		fmt.Fprintf(c.ErrOrStderr(), "  Get an API key at: %s\n", tmpl.DocsURL)
	}
}

// newPhase3ListCmd returns the Phase 3 `list` command (provider/account/namespace columns).
//
//nolint:unused // planned: wired into connect command in Phase 3 promotion
func newPhase3ListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List connections (provider/account/namespace, no values)",
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()
			cfg := loadCLIConfig(c)
			store := newDispatchedStore(cfg, llmcontext.DefaultLookup)
			namespace, _ := c.Flags().GetString("namespace")

			statuses, err := connections.Status(ctx, connections.StatusOptions{Namespace: namespace}, store)
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				os.Exit(exitcode.OperationFailed)
			}

			useJSON, _ := c.Flags().GetBool("json")
			if useJSON {
				data, _ := json.Marshal(statuses)
				fmt.Fprintln(c.OutOrStdout(), string(data))
				return nil
			}

			fmt.Fprintf(c.OutOrStdout(), "%-20s %-15s %-12s %-20s\n",
				"PROVIDER", "ACCOUNT", "NAMESPACE", "RUNTIME")
			for _, s := range statuses {
				fmt.Fprintf(c.OutOrStdout(), "%-20s %-15s %-12s %-20s\n",
					s.Connection.Provider,
					s.Connection.Account,
					s.Connection.Namespace,
					string(s.Connection.Runtime),
				)
			}
			return nil
		},
	}
}

// resolveProviderRefs validates --provider-ref field=URI flags and stores the
// URI (not the resolved plaintext) in fields.
//
// EPIC-10 (T-10-01): --provider-ref defers resolution to runtime. The URI is
// written to the vault verbatim so the resolver can be invoked each time the
// credential is needed. This upholds two security invariants:
//   - S-EXT-3: the external store is the authoritative source; no plaintext copy lives in keylatch.
//   - S-EXT-4: rotation in the upstream PM is picked up automatically on next use.
//
// Each flag has the format "field-name=uri" where uri is one of:
//   - op://vault/item/field
//   - aws-sm://region/secret-id[#key]
//   - hashivault://mount/path[#field]
//
// Dry-run validation: the URI is parsed and scheme-checked before any write
// occurs. An invalid URI returns a UsageError (exit UserError) before persistence.
func resolveProviderRefs(_ context.Context, flags []string, fields map[string][]byte) error {
	for _, kv := range flags {
		idx := strings.Index(kv, "=")
		if idx < 0 {
			return fmt.Errorf("invalid --provider-ref format %q; expected field=uri", kv)
		}
		fieldName := kv[:idx]
		uri := kv[idx+1:]
		if fieldName == "" {
			return fmt.Errorf("invalid --provider-ref: field name is empty in %q", kv)
		}
		if uri == "" {
			return fmt.Errorf("invalid --provider-ref: URI is empty for field %q", fieldName)
		}

		if _, alreadySet := fields[fieldName]; alreadySet {
			return fmt.Errorf("field %q: set by both --field and --provider-ref; use one or the other", fieldName)
		}

		// Dry-run validation: confirm scheme is supported before any write.
		if err := store.ValidateProviderRefURI(uri); err != nil {
			return NewUsageError("--provider-ref field %q: %v", fieldName, err)
		}

		// Store the URI verbatim. Resolution is deferred to runtime via
		// internal/store.Resolver so the external PM is always the source of truth.
		fields[fieldName] = []byte(uri)
	}
	return nil
}
