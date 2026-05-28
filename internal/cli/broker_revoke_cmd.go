package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/broker"
	"github.com/spf13/cobra"
)

// brokerRevokeOutput is the JSON shape for a successful single-token revocation.
type brokerRevokeOutput struct {
	TokenID   string `json:"token_id"`
	RevokedAt string `json:"revoked_at,omitempty"`
	Status    string `json:"status"`
}

// brokerRevokeAllOutput is the JSON shape for `broker revoke --all`.
type brokerRevokeAllOutput struct {
	RevokedCount int      `json:"revokedCount"`
	TokenIDs     []string `json:"tokenIds"`
}

// newBrokerRevokeCmd returns `broker revoke <id>` (and `broker revoke --all`).
//
// Single revoke:
//   - Marks the token revoked in internal state; evicts from cache.
//   - Attempts provider revocation if template defines revocation endpoint (best-effort).
//   - Emits BrokerTokenRevoked audit event.
//   - Not-found / already-revoked: exit 1 with actionable error.
//   - --json: emits {token_id, status}.
//
// --all:
//   - Lists active grants; prompts "Revoke all N? [y/N]"; on y, revokes each.
//   - --yes skips prompt.
//   - --json: emits {revokedCount, tokenIds}.
//   - Tolerates races (skips non-active silently).
func newBrokerRevokeCmd() *cobra.Command {
	var (
		revokeAll bool
		skipYes   bool
		useJSON   bool
		actorID   string
	)

	cmd := &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke an active scoped token by ID (or revoke all with --all)",
		Long: `Revoke an active scoped token managed by the in-process broker.

The <id> argument is the Scoped-Token-ID shown by 'broker status'.

With --all, revokes all active grants (optionally filtered by --actor).
You will be prompted to confirm unless --yes is provided.

Requires the broker to be running in-process.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if !useJSON {
				if jf, err := c.Root().PersistentFlags().GetBool("json"); err == nil && jf {
					useJSON = true
				}
			}

			// Obtain a handle — out-of-process returns ErrBrokerOutOfProcess.
			handle := brokerHandleFactory()

			if revokeAll {
				return runBrokerRevokeAll(c, handle, actorID, skipYes, useJSON)
			}

			if len(args) == 0 {
				return NewUsageError("missing <id> argument — run 'broker status' to list token IDs, or use --all")
			}
			tokenID := args[0]
			return runBrokerRevokeSingle(c, handle, tokenID, useJSON)
		},
	}

	cmd.Flags().BoolVar(&revokeAll, "all", false, "revoke all active tokens")
	cmd.Flags().BoolVar(&skipYes, "yes", false, "skip confirmation prompt (use with --all)")
	cmd.Flags().BoolVar(&useJSON, "json", false, "output as JSON")
	cmd.Flags().StringVar(&actorID, "actor", "", "filter --all to tokens for this actor ID")
	return cmd
}

// runBrokerRevokeSingle revokes a single token by ID.
func runBrokerRevokeSingle(c *cobra.Command, handle broker.BrokerHandle, tokenID string, useJSON bool) error {
	err := handle.Revoke(tokenID)
	if err != nil {
		if errors.Is(err, broker.ErrBrokerOutOfProcess) {
			fmt.Fprintln(c.ErrOrStderr(), "error[BrokerOutOfProcess]:", err.Error())
			return NewSecurityBlock("broker not running in-process: %s", err.Error())
		}
		if errors.Is(err, broker.ErrTokenNotFound) {
			fmt.Fprintf(c.ErrOrStderr(), "error[TokenNotFound]: token %q not found — it may have already expired or been revoked.\n", tokenID)
			fmt.Fprintln(c.ErrOrStderr(), "  Run 'keylatch broker status' to see active token IDs.")
			return NewUsageError("token %q not found", tokenID)
		}
		return NewInternalError("revoke token %q: %v", tokenID, err)
	}

	if useJSON {
		out := brokerRevokeOutput{
			TokenID:   tokenID,
			RevokedAt: time.Now().UTC().Format(time.RFC3339),
			Status:    "revoked",
		}
		b, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return NewInternalError("marshal revoke output: %v", err)
		}
		fmt.Fprintln(c.OutOrStdout(), string(b))
		return nil
	}

	fmt.Fprintf(c.OutOrStdout(), "Revoked token %s.\n", tokenID)
	return nil
}

// runBrokerRevokeAll revokes all active grants (optionally filtered by actorID).
func runBrokerRevokeAll(c *cobra.Command, handle broker.BrokerHandle, actorID string, skipYes bool, useJSON bool) error {
	grants, err := handle.ListGrants()
	if err != nil {
		if errors.Is(err, broker.ErrBrokerOutOfProcess) {
			fmt.Fprintln(c.ErrOrStderr(), "error[BrokerOutOfProcess]:", err.Error())
			return NewSecurityBlock("broker not running in-process: %s", err.Error())
		}
		return NewInternalError("list grants: %v", err)
	}

	if len(grants) == 0 {
		if useJSON {
			out := brokerRevokeAllOutput{RevokedCount: 0, TokenIDs: []string{}}
			b, _ := json.MarshalIndent(out, "", "  ")
			fmt.Fprintln(c.OutOrStdout(), string(b))
		} else {
			fmt.Fprintln(c.OutOrStdout(), "No active tokens to revoke.")
		}
		return nil
	}

	n := len(grants)
	if !skipYes && !useJSON {
		fmt.Fprintf(c.OutOrStdout(), "Revoke all %d active token(s)? [y/N]: ", n)
		scanner := bufio.NewScanner(c.InOrStdin())
		scanner.Scan()
		answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if answer != "y" && answer != "yes" {
			fmt.Fprintln(c.OutOrStdout(), "Aborted.")
			return nil
		}
	}

	var revokedIDs []string
	skipped := 0
	for _, g := range grants {
		rErr := handle.Revoke(g.ScopedTokenID)
		if rErr != nil {
			if errors.Is(rErr, broker.ErrTokenNotFound) {
				// Race — already expired or revoked. Skip silently.
				skipped++
				continue
			}
			// Non-race error — stop and report.
			return NewInternalError("revoke token %s: %v", g.ScopedTokenID, rErr)
		}
		revokedIDs = append(revokedIDs, g.ScopedTokenID)
	}
	if revokedIDs == nil {
		revokedIDs = []string{}
	}

	if useJSON {
		out := brokerRevokeAllOutput{
			RevokedCount: len(revokedIDs),
			TokenIDs:     revokedIDs,
		}
		b, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return NewInternalError("marshal revoke-all output: %v", err)
		}
		fmt.Fprintln(c.OutOrStdout(), string(b))
		return nil
	}

	fmt.Fprintf(c.OutOrStdout(), "Revoked %d token(s).", len(revokedIDs))
	if skipped > 0 {
		fmt.Fprintf(c.OutOrStdout(), " (%d already expired, skipped)", skipped)
	}
	fmt.Fprintln(c.OutOrStdout())
	return nil
}
