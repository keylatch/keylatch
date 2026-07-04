// Package cli — approve subcommand (production).
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/keylatch/keylatch/internal/cmderr"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/gateway/approval"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/spf13/cobra"
)

// approveOutput is the JSON shape for `keylatch approve --json`.
// No credential values are present.
type approveOutput struct {
	Token   string `json:"token"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message"`
}

// approveListEntry is the JSON shape for a single entry in `keylatch approve list --json`.
type approveListEntry struct {
	Token        string `json:"token"`
	Provider     string `json:"provider"`
	Agent        string `json:"agent"`
	RequestedAt  string `json:"requested_at"`
	TTLRemaining string `json:"ttl_remaining"`
	Status       string `json:"status"`
}

// newApproveCmd returns the `approve` subcommand.
// Registered unconditionally in root.go (not behind experimental gate).
func newApproveCmd() *cobra.Command {
	var reason string
	var useJSON bool

	cmd := &cobra.Command{
		Use:   "approve <token>",
		Short: "Approve a pending secret-access request",
		Long: `Approve a pending secret-access request by token.

The token is the approval ID returned by 'keylatch ui' or by the
Approval Inbox SSE stream. Use 'keylatch approve <token> --reason "why"'
to record a reason for the approval.

This command is blocked inside LLM sessions (CREDENTIALS_LLM_SESSION or
CLAUDE_CODE env vars set). Approvals must be performed by a human operator.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			env := llmcontext.DefaultLookup

			// LLM session guard: approvals must not run inside LLM sessions.
			if llmcontext.IsLLMSession(env) {
				cerr := cmderr.Wrap(
					"approve: command is not permitted inside an LLM session",
					nil,
					"Approvals must be performed by a human operator outside of an LLM session.",
					"KL-4101",
				)
				cmderr.Format(c.ErrOrStderr(), cerr)
				return NewSecurityBlock("approve: command is not permitted inside an LLM session")
			}

			token := args[0]
			approvalsDir := paths.ApprovalsDir(env)

			if err := approval.ApproveWithReason(c.Context(), approvalsDir, token, reason); err != nil {
				if errors.Is(err, approval.ErrNotFound) {
					cerr := cmderr.Wrap(
						fmt.Sprintf("approval %q not found", token),
						err,
						"Check the token with 'keylatch ui' or the Approval Inbox.",
						"KL-4102",
					)
					cmderr.Format(c.ErrOrStderr(), cerr)
					return &CLIError{Class: "Missing", Code: exitcode.Missing, Message: cerr.Summary}
				}
				// ErrExpiredTTL satisfies errors.Is(ErrExpired) and ErrAlreadyActed.
				var expErr *approval.ErrExpiredTTL
				if errors.As(err, &expErr) {
					cerr := cmderr.Wrap(
						fmt.Sprintf("approval %q %s", token, expErr.Error()),
						err,
						"The request TTL has elapsed. Ask the agent to re-submit.",
						"KL-4104",
					)
					cmderr.Format(c.ErrOrStderr(), cerr)
					return &CLIError{Class: "UserError", Code: exitcode.UserError, Message: cerr.Summary}
				}
				if errors.Is(err, approval.ErrAlreadyActed) {
					cerr := cmderr.Wrap(
						fmt.Sprintf("approval %q has already been approved or denied", token),
						err,
						"",
						"KL-4103",
					)
					cmderr.Format(c.ErrOrStderr(), cerr)
					return &CLIError{Class: "UserError", Code: exitcode.UserError, Message: cerr.Summary}
				}
				cerr := cmderr.Wrap(
					fmt.Sprintf("failed to approve %q", token),
					err,
					"",
					"KL-4100",
				)
				cmderr.Format(c.ErrOrStderr(), cerr)
				return &CLIError{Class: "OperationFailed", Code: exitcode.OperationFailed, Message: cerr.Summary}
			}

			out := approveOutput{
				Token:   token,
				Status:  "approved",
				Reason:  reason,
				Message: fmt.Sprintf("approval %q marked as approved", token),
			}

			if useJSON {
				b, _ := json.MarshalIndent(out, "", "  ")
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}

			fmt.Fprintf(c.OutOrStdout(), "approved: %s\n", token)
			if reason != "" {
				fmt.Fprintf(c.OutOrStdout(), "reason: %s\n", reason)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&reason, "reason", "", "reason for the approval (recorded in approval record)")
	cmd.Flags().BoolVar(&useJSON, "json", false, "output result as JSON")

	// Add `approve list` subcommand.
	cmd.AddCommand(newApproveListCmd())

	return cmd
}

// newApproveListCmd returns the `approve list` subcommand.
func newApproveListCmd() *cobra.Command {
	var useJSON bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List pending approval requests",
		Long: `List all pending approval requests.

Displays token, provider, agent, requested-at timestamp, and TTL remaining.
Requests past their TTL are shown with status "expired" — they will be
swept by the background process and can no longer be acted upon.

Use --json to emit a JSON array for scripting.`,
		RunE: func(c *cobra.Command, _ []string) error {
			env := llmcontext.DefaultLookup
			approvalsDir := paths.ApprovalsDir(env)

			requests, err := approval.List(c.Context(), approvalsDir)
			if err != nil {
				return fmt.Errorf("approve list: %w", err)
			}

			if len(requests) == 0 {
				if useJSON {
					fmt.Fprintln(c.OutOrStdout(), "[]")
					return nil
				}
				fmt.Fprintln(c.OutOrStdout(), "No pending approvals.")
				return nil
			}

			now := time.Now().UTC()

			if useJSON {
				entries := make([]approveListEntry, 0, len(requests))
				for _, ar := range requests {
					remaining := ar.ExpiresAt.Sub(now)
					ttlStr := formatTTL(remaining)
					entries = append(entries, approveListEntry{
						Token:        ar.Token,
						Provider:     ar.Connection,
						Agent:        ar.Actor,
						RequestedAt:  ar.CreatedAt.UTC().Format(time.RFC3339),
						TTLRemaining: ttlStr,
						Status:       ar.Status,
					})
				}
				b, _ := json.MarshalIndent(entries, "", "  ")
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}

			w := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tPROVIDER\tAGENT\tREQUESTED-AT\tTTL-REMAINING\tSTATUS")
			for _, ar := range requests {
				remaining := ar.ExpiresAt.Sub(now)
				ttlStr := formatTTL(remaining)
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					ar.Token,
					ar.Connection,
					ar.Actor,
					ar.CreatedAt.UTC().Format(time.RFC3339),
					ttlStr,
					ar.Status,
				)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&useJSON, "json", false, "output as JSON array")
	return cmd
}

// formatTTL formats a duration for TTL display. Negative values show "expired".
func formatTTL(d time.Duration) string {
	if d <= 0 {
		return "expired"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}
