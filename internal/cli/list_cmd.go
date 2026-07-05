package cli

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runtime"
	"github.com/keylatch/keylatch/internal/vault"
	"github.com/spf13/cobra"
)

// usableReason returns ("yes", "") when the connection can be used in the current session,
// or ("no", reason) when it cannot.
// LLM sessions may only use gateway modes; non-LLM sessions may use any mode.
func usableReason(conn connections.Connection, isLLM bool) (usable string, reason string) {
	tmpl, err := registry.Get(conn.Provider)
	if err != nil {
		return "no", "unknown-provider"
	}
	// Check if any supported mode is usable in this session.
	for _, m := range tmpl.RuntimeSupport.Supported {
		rm := runtime.RuntimeMode(m)
		if isLLM {
			// LLM sessions can only use gateway/brokered modes.
			switch rm {
			case runtime.RuntimeGatewayTyped, runtime.RuntimeGatewaySDK,
				runtime.RuntimeDirectBrokered, runtime.RuntimeGatewayProxy:
				return "yes", ""
			}
		} else {
			return "yes", ""
		}
	}
	if isLLM {
		return "no", "llm-session"
	}
	return "no", "no-gateway"
}

// newListCmdImpl returns the extended `list` command that uses vault.List
// via the dispatcher. Replaces the stub in root.go.
// Output is metadata only — no credential values.
// Provider-centric table view with --raw flag for vault-path output.
// Adds USABLE column and --json flag.
func newListCmdImpl() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List credential connections (provider-centric table)",
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()
			cfg := loadCLIConfig(c)
			env := llmcontext.DefaultLookup

			// Inject audit emitter into context (best-effort: warn if audit
			// logger cannot be opened, e.g. keyring not set up).
			if al, cleanup, auditErr := openAuditLogger(); auditErr == nil {
				defer cleanup()
				ctx = audit.WithEmitter(ctx, audit.AsEmitter(al))
			} else {
				fmt.Fprintf(c.ErrOrStderr(), "warning: audit logger unavailable (%v) — vault operations will not be audited\n", auditErr)
			}

			raw, _ := c.Flags().GetBool("raw")
			useJSON, _ := c.Flags().GetBool("json")

			if raw {
				// --raw: restore the old vault-path output for power users.
				entries, err := vault.List(ctx, "", cfg, env)
				if err != nil {
					fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
					return err
				}

				b, err := dispatch.Select(ctx, cfg, env)
				if err != nil {
					fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
					return err
				}

				backendName := b.Name()
				for _, e := range entries {
					fmt.Fprintf(c.OutOrStdout(), "%s/%s\n", backendName, e.Path)
				}
				return nil
			}

			// Provider-centric view using connections.Status.
			store := newDispatchedStore(cfg, env)
			statuses, err := connections.Status(ctx, connections.StatusOptions{
				Namespace: "default",
			}, store)
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				return err
			}

			b, bErr := dispatch.Select(ctx, cfg, env)
			backendName := "file"
			if bErr == nil {
				backendName = b.Name()
			}

			isLLM := llmcontext.IsLLMSession(env)

			if useJSON {
				type listEntry struct {
					Provider string `json:"provider"`
					Account  string `json:"account"`
					Status   string `json:"status"`
					Usable   string `json:"usable"`
					Reason   string `json:"reason,omitempty"`
				}
				out := make([]listEntry, 0, len(statuses))
				for _, s := range statuses {
					u, r := usableReason(s.Connection, isLLM)
					out = append(out, listEntry{
						Provider: s.Connection.Provider,
						Account:  s.Connection.Account,
						Status:   string(s.Connection.Status),
						Usable:   u,
						Reason:   r,
					})
				}
				_ = json.NewEncoder(c.OutOrStdout()).Encode(out)
				return nil
			}

			if len(statuses) == 0 {
				fmt.Fprintln(c.OutOrStdout(), "No connections yet — run `keylatch connect <provider>`")
				return nil
			}

			w := tabwriter.NewWriter(c.OutOrStdout(), 0, 0, 3, ' ', 0)
			fmt.Fprintf(w, "PROVIDER\tACCOUNT\tSTATUS\tLAST USED\tEXPIRES\tUSABLE\n")
			for _, s := range statuses {
				lastUsed := relativeTime(s.Connection.LastTested)
				u, r := usableReason(s.Connection, isLLM)
				usableCol := u
				if r != "" {
					usableCol = u + " (" + r + ")"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					s.Connection.Provider,
					s.Connection.Account,
					s.Connection.Status,
					lastUsed,
					"never",
					usableCol,
				)
			}
			w.Flush() //nolint:errcheck // non-critical output error

			fmt.Fprintln(c.OutOrStdout())
			fmt.Fprintf(c.OutOrStdout(), "%d connections (%s backend)\n", len(statuses), backendName)
			fmt.Fprintln(c.OutOrStdout())
			fmt.Fprintln(c.OutOrStdout(), "  keylatch test <provider>           verify a connection works")
			fmt.Fprintln(c.OutOrStdout(), "  keylatch describe <provider>       show what's stored")
			fmt.Fprintln(c.OutOrStdout(), "  keylatch list --raw                show vault paths (advanced)")
			return nil
		},
	}
	cmd.Flags().Bool("raw", false, "show vault paths instead of connection table (advanced)")
	cmd.Flags().Bool("json", false, "output as JSON")
	return cmd
}
