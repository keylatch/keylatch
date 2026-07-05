// Package cli — deny subcommand (production).
package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/keylatch/keylatch/internal/cmderr"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/gateway/approval"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/spf13/cobra"
)

// denyOutput is the JSON shape for `keylatch deny --json`.
// No credential values are present.
type denyOutput struct {
	Token   string `json:"token"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message"`
}

// denyAllOutput is the JSON shape for `keylatch deny --all --json`.
type denyAllOutput struct {
	DeniedCount int      `json:"deniedCount"`
	RequestIDs  []string `json:"requestIds"`
}

// newDenyCmd returns the `deny` subcommand.
// Registered unconditionally in root.go (not behind experimental gate).
func newDenyCmd() *cobra.Command {
	var reason string
	var useJSON bool
	var denyAll bool
	var skipPrompt bool

	cmd := &cobra.Command{
		Use:   "deny [<token>]",
		Short: "Deny a pending secret-access request",
		Long: `Deny a pending secret-access request by token.

The token is the approval ID returned by 'keylatch ui' or by the
Approval Inbox SSE stream. Use 'keylatch deny <token> --reason "why"'
to record a reason for the denial (recommended for audit trail).

Use --all to deny every pending approval in one operation. You will be
prompted to confirm unless --yes is also set. --json emits
{"deniedCount": N, "requestIds": [...]} on success.

This command is blocked inside LLM sessions (CREDENTIALS_LLM_SESSION or
CLAUDE_CODE env vars set). Denials must be performed by a human operator.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			env := llmcontext.DefaultLookup

			// LLM session guard: denials must not run inside LLM sessions.
			if llmcontext.IsLLMSession(env) {
				cerr := cmderr.Wrap(
					"deny: command is not permitted inside an LLM session",
					nil,
					"Denials must be performed by a human operator outside of an LLM session.",
					"KL-4111",
				)
				cmderr.Format(c.ErrOrStderr(), cerr)
				return NewSecurityBlock("deny: command is not permitted inside an LLM session")
			}

			approvalsDir := paths.ApprovalsDir(env)

			// --all mode: deny every pending approval.
			if denyAll {
				return runDenyAll(c, approvalsDir, reason, skipPrompt, useJSON)
			}

			// Single-token mode.
			if len(args) == 0 {
				return fmt.Errorf("deny: requires a <token> argument or --all flag")
			}
			token := args[0]

			if err := approval.DenyWithReason(c.Context(), approvalsDir, token, reason); err != nil {
				if errors.Is(err, approval.ErrNotFound) {
					cerr := cmderr.Wrap(
						fmt.Sprintf("approval %q not found", token),
						err,
						"Check the token with 'keylatch ui' or the Approval Inbox.",
						"KL-4112",
					)
					cmderr.Format(c.ErrOrStderr(), cerr)
					return &CLIError{Class: "Missing", Code: exitcode.Missing, Message: cerr.Summary}
				}
				// ErrExpiredTTL satisfies errors.Is(ErrAlreadyActed) — check it first.
				var expErr *approval.ErrExpiredTTL
				if errors.As(err, &expErr) {
					cerr := cmderr.Wrap(
						fmt.Sprintf("approval %q %s", token, expErr.Error()),
						err,
						"The request TTL has elapsed. Ask the agent to re-submit.",
						"KL-4114",
					)
					cmderr.Format(c.ErrOrStderr(), cerr)
					return &CLIError{Class: "UserError", Code: exitcode.UserError, Message: cerr.Summary}
				}
				if errors.Is(err, approval.ErrAlreadyActed) {
					cerr := cmderr.Wrap(
						fmt.Sprintf("approval %q has already been approved or denied", token),
						err,
						"",
						"KL-4113",
					)
					cmderr.Format(c.ErrOrStderr(), cerr)
					return &CLIError{Class: "UserError", Code: exitcode.UserError, Message: cerr.Summary}
				}
				cerr := cmderr.Wrap(
					fmt.Sprintf("failed to deny %q", token),
					err,
					"",
					"KL-4110",
				)
				cmderr.Format(c.ErrOrStderr(), cerr)
				return &CLIError{Class: "OperationFailed", Code: exitcode.OperationFailed, Message: cerr.Summary}
			}

			out := denyOutput{
				Token:   token,
				Status:  "denied",
				Reason:  reason,
				Message: fmt.Sprintf("approval %q marked as denied", token),
			}

			if useJSON {
				b, _ := json.MarshalIndent(out, "", "  ")
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}

			fmt.Fprintf(c.OutOrStdout(), "denied: %s\n", token)
			if reason != "" {
				fmt.Fprintf(c.OutOrStdout(), "reason: %s\n", reason)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&reason, "reason", "", "reason for the denial (recorded in approval record)")
	cmd.Flags().BoolVar(&useJSON, "json", false, "output result as JSON")
	cmd.Flags().BoolVar(&denyAll, "all", false, "deny all pending approvals")
	cmd.Flags().BoolVar(&skipPrompt, "yes", false, "skip confirmation prompt when using --all")
	return cmd
}

// runDenyAll implements the --all flag: list pending, prompt, deny each.
func runDenyAll(c *cobra.Command, approvalsDir, reason string, skipPrompt, useJSON bool) error {
	ctx := c.Context()

	// List all pending (non-expired) approvals.
	pending, err := approval.Pending(ctx, approvalsDir)
	if err != nil {
		return fmt.Errorf("deny --all: %w", err)
	}

	if len(pending) == 0 {
		if useJSON {
			out := denyAllOutput{DeniedCount: 0, RequestIDs: []string{}}
			b, _ := json.MarshalIndent(out, "", "  ")
			fmt.Fprintln(c.OutOrStdout(), string(b))
			return nil
		}
		fmt.Fprintln(c.OutOrStdout(), "No pending approvals.")
		return nil
	}

	// Prompt unless --yes was given.
	if !skipPrompt {
		fmt.Fprintf(c.OutOrStdout(), "Deny all %d pending approvals? [y/N] ", len(pending))
		reader := bufio.NewReader(c.InOrStdin())
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(strings.ToLower(line))
		if line != "y" && line != "yes" {
			fmt.Fprintln(c.OutOrStdout(), "Aborted.")
			return nil
		}
	}

	// Deny each — tolerate races (skip non-pending silently).
	var deniedIDs []string
	for _, ar := range pending {
		err := approval.DenyWithReason(ctx, approvalsDir, ar.Token, reason)
		if err == nil {
			deniedIDs = append(deniedIDs, ar.Token)
			continue
		}
		// Race: already decided or not found — skip silently.
		if errors.Is(err, approval.ErrAlreadyActed) || errors.Is(err, approval.ErrNotFound) {
			continue
		}
		// Unexpected error — surface it.
		return fmt.Errorf("deny --all: %w", err)
	}

	if useJSON {
		ids := deniedIDs
		if ids == nil {
			ids = []string{}
		}
		out := denyAllOutput{DeniedCount: len(deniedIDs), RequestIDs: ids}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Fprintln(c.OutOrStdout(), string(b))
		return nil
	}

	fmt.Fprintf(c.OutOrStdout(), "denied %d approval(s).\n", len(deniedIDs))
	return nil
}
