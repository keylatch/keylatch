package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"text/tabwriter"

	"github.com/keylatch/keylatch/internal/broker"
	"github.com/spf13/cobra"
)

// brokerDryRunOutput is the value-free dry-run result payload.
// NEVER contains actual token bytes or credential values.
type brokerDryRunOutput struct {
	Provider        string   `json:"provider"`
	Command         string   `json:"command"`
	ScopesRequested []string `json:"scopes_requested"`
	ScopedTokenTTL  string   `json:"scoped_token_ttl"`
	PolicyDecision  string   `json:"policy_decision"`
	Reason          string   `json:"reason"`
}

// newBrokerDryRunCmd returns `broker dry-run <provider> <command>`.
//
// Prints a structured report without calling the provider token-exchange
// endpoint, without issuing a token, and without mutating the cache.
// Emits a BrokerDryRunRequested audit event.
func newBrokerDryRunCmd() *cobra.Command {
	var useJSON bool

	cmd := &cobra.Command{
		Use:   "dry-run <provider> <command>",
		Short: "Simulate a broker token exchange without performing it (no token issued)",
		Long: `Simulate a broker token exchange for a provider and command.

Does NOT call the provider token endpoint, does NOT issue a token, and does
NOT mutate the broker cache. Emits a BrokerDryRunRequested audit event.

Output columns: Provider | Scopes-Requested | Scoped-Token-TTL | Policy-Decision | Reason

Requires the broker to be running in-process.`,
		Args: cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			provider := args[0]
			command := args[1]

			if !useJSON {
				// Also check root persistent --json flag.
				if jf, err := c.Root().PersistentFlags().GetBool("json"); err == nil && jf {
					useJSON = true
				}
			}

			// Obtain a handle — out-of-process returns ErrBrokerOutOfProcess.
			handle := brokerHandleFactory()

			result, err := handle.DryRunExchange(provider, command)
			if err != nil {
				if errors.Is(err, broker.ErrBrokerOutOfProcess) {
					fmt.Fprintln(c.ErrOrStderr(), "error[BrokerOutOfProcess]:", err.Error())
					return NewSecurityBlock("broker not running in-process: %s", err.Error())
				}
				if errors.Is(err, broker.ErrProviderNoBrokerConfig) {
					fmt.Fprintf(c.ErrOrStderr(), "error[ProviderNoBrokerConfig]: %v\n", err)
					fmt.Fprintf(c.ErrOrStderr(), "  Provider %q has no broker configuration.\n", provider)
					fmt.Fprintln(c.ErrOrStderr(), "  Run 'keylatch list' to see configured providers.")
					return NewUsageError("provider %q has no broker configuration", provider)
				}
				return NewInternalError("dry-run exchange: %v", err)
			}

			ttlStr := result.ScopedTokenTTL.String()
			output := brokerDryRunOutput{
				Provider:        result.Provider,
				Command:         command,
				ScopesRequested: result.ScopesRequested,
				ScopedTokenTTL:  ttlStr,
				PolicyDecision:  result.PolicyDecision,
				Reason:          result.Reason,
			}

			if useJSON {
				b, err := json.MarshalIndent(output, "", "  ")
				if err != nil {
					return NewInternalError("marshal dry-run output: %v", err)
				}
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}

			// Table output.
			tw := tabwriter.NewWriter(c.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "FIELD\tVALUE")
			fmt.Fprintf(tw, "provider\t%s\n", output.Provider)
			fmt.Fprintf(tw, "command\t%s\n", output.Command)
			scopesStr := ""
			for i, s := range output.ScopesRequested {
				if i > 0 {
					scopesStr += ", "
				}
				scopesStr += s
			}
			fmt.Fprintf(tw, "scopes_requested\t%s\n", scopesStr)
			fmt.Fprintf(tw, "scoped_token_ttl\t%s\n", output.ScopedTokenTTL)
			fmt.Fprintf(tw, "policy_decision\t%s\n", output.PolicyDecision)
			fmt.Fprintf(tw, "reason\t%s\n", output.Reason)
			return tw.Flush()
		},
	}

	cmd.Flags().BoolVar(&useJSON, "json", false, "output as JSON")
	return cmd
}
