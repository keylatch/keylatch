// Package cli — deny subcommand (production).
package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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

Denials must be performed by a human operator: the command requires an
interactive terminal on stdin, is refused inside a detected LLM session
(see 'keylatch env' for the recognized signals) and asks for the approver
passphrase set with 'keylatch approve init'.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := requireHumanApprover("deny", "KL-4111", "KL-4115"); err != nil {
				return err
			}

			approvalsDir := paths.ApprovalsDir(llmcontext.DefaultLookup)

			if denyAll {
				return runDenyAll(c, approvalsDir, reason, skipPrompt, useJSON)
			}

			if len(args) == 0 {
				return fmt.Errorf("deny: requires a <token> argument or --all flag")
			}
			token := args[0]

			ar, err := approval.Get(c.Context(), approvalsDir, token)
			if err == nil {
				err = undecided(ar)
			}
			if err != nil {
				return denyError(token, err)
			}
			printApprovalSummary(c.ErrOrStderr(), ar)

			key, err := unlockApprover("deny", "KL-4116", "KL-4117")
			if err != nil {
				return err
			}
			defer clear(key)

			if err := approval.DenyWithReason(c.Context(), approvalsDir, token, approval.Digest(ar), reason, key); err != nil {
				return denyError(token, err)
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

	key, err := unlockApprover("deny --all", "KL-4116", "KL-4117")
	if err != nil {
		return err
	}
	defer clear(key)

	// Deny each — tolerate races (skip non-pending silently).
	var deniedIDs []string
	for _, ar := range pending {
		err := approval.DenyWithReason(ctx, approvalsDir, ar.Token, approval.Digest(&ar), reason, key)
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

// denyError maps approval package errors to CLI errors for deny.
func denyError(token string, err error) error {
	if errors.Is(err, approval.ErrNotFound) {
		return &CLIError{
			Class:   "Missing",
			Code:    exitcode.Missing,
			Message: fmt.Sprintf("approval %q not found. Check the token with 'keylatch approve list'. (KL-4112)", token),
		}
	}
	// ErrExpiredTTL satisfies errors.Is(ErrAlreadyActed) — check it first.
	var expErr *approval.ErrExpiredTTL
	if errors.As(err, &expErr) {
		return &CLIError{
			Class:   "UserError",
			Code:    exitcode.UserError,
			Message: fmt.Sprintf("approval %q %s. The request TTL has elapsed. Ask the agent to re-submit. (KL-4114)", token, expErr.Error()),
		}
	}
	if errors.Is(err, approval.ErrAlreadyActed) {
		return &CLIError{
			Class:   "UserError",
			Code:    exitcode.UserError,
			Message: fmt.Sprintf("approval %q has already been approved or denied. (KL-4113)", token),
		}
	}
	if errors.Is(err, approval.ErrChanged) || errors.Is(err, approval.ErrTTLTooLong) {
		return NewSecurityBlock("approval %q refused: %v. Nothing was signed. (KL-4119)", token, err)
	}
	return &CLIError{
		Class:   "OperationFailed",
		Code:    exitcode.OperationFailed,
		Message: fmt.Sprintf("failed to deny %q: %v. (KL-4110)", token, err),
	}
}
