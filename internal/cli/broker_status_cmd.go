package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/keylatch/keylatch/internal/broker"
	"github.com/spf13/cobra"
)

// brokerStatusGrantRow is a single value-free row in the status table.
// Token values (sk-..., JWT) are NEVER included.
type brokerStatusGrantRow struct {
	Provider      string `json:"provider"`
	ActorHMAC     string `json:"actor_hmac"`
	ScopedTokenID string `json:"scoped_token_id"`
	ExpiresAt     string `json:"expires_at"`
	InsertedAt    string `json:"inserted_at"`
}

// brokerStatusOutput is the full JSON payload for `broker status --json`.
type brokerStatusOutput struct {
	Grants []brokerStatusGrantRow `json:"grants"`
	Total  int                    `json:"total"`
}

// newBrokerStatusCmd returns `broker status`.
//
// Table columns: Provider | Actor-HMAC | Scoped-Token-ID | Expires-At | Inserted-At
// Empty state: "No active scoped tokens."
// Out-of-process: exit 2 with ErrBrokerOutOfProcess message.
// No token value (sk-..., JWT) appears in any output path.
func newBrokerStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show active scoped tokens (no credential values)",
		Long: `Show metadata for all active scoped tokens managed by the in-process broker.

No credential values (sk-..., JWT, etc.) are ever included in the output.
Columns: Provider | Actor-HMAC | Scoped-Token-ID | Expires-At | Inserted-At

Requires the broker to be running in-process. If the broker is owned by a
separate gateway process, use 'keylatch gateway status' instead.`,
		RunE: func(c *cobra.Command, _ []string) error {
			jsonOut, _ := c.Root().PersistentFlags().GetBool("json")

			// Obtain a handle — out-of-process returns ErrBrokerOutOfProcess.
			handle := brokerHandleFactory()

			grants, err := handle.ListGrants()
			if err != nil {
				if errors.Is(err, broker.ErrBrokerOutOfProcess) {
					// Out-of-process — actionable error, exit 2. Returns a
					// *CLIError without printing directly — main.go prints
					// it exactly once (C5); printing here too would
					// double-print (Finding-001).
					return NewSecurityBlock("broker not running in-process: %s", err.Error())
				}
				return NewInternalError("list grants: %v", err)
			}

			rows := make([]brokerStatusGrantRow, 0, len(grants))
			for _, g := range grants {
				rows = append(rows, brokerStatusGrantRow{
					Provider:      g.Provider,
					ActorHMAC:     g.ActorHMAC,
					ScopedTokenID: g.ScopedTokenID,
					ExpiresAt:     g.ExpiresAt.UTC().Format(time.RFC3339),
					InsertedAt:    g.InsertedAt.UTC().Format(time.RFC3339),
				})
			}

			output := brokerStatusOutput{
				Grants: rows,
				Total:  len(rows),
			}

			if jsonOut {
				b, err := json.MarshalIndent(output, "", "  ")
				if err != nil {
					return NewInternalError("marshal broker status: %v", err)
				}
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}

			// Table output.
			if len(rows) == 0 {
				fmt.Fprintln(c.OutOrStdout(), "No active scoped tokens.")
				return nil
			}
			tw := tabwriter.NewWriter(c.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "PROVIDER\tACTOR-HMAC\tSCOPED-TOKEN-ID\tEXPIRES-AT\tINSERTED-AT")
			for _, r := range rows {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					r.Provider, r.ActorHMAC, r.ScopedTokenID, r.ExpiresAt, r.InsertedAt)
			}
			return tw.Flush()
		},
	}
	return cmd
}
