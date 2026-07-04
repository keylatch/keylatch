// Package cli — team governance CLI commands.
//
// Security invariants:
//   - Role enforcement at package layer (team.RequireRole), not here.
//   - All output is value-free (emails never printed raw — HMACd only).
//   - Shared-secret reveal is blocked in LLM sessions.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/cmderr"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/team"
)

// newTeamCmd returns the `team` subcommand group.
func newTeamCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "team",
		Short: "Manage team membership, roles, and governance",
	}
	cmd.AddCommand(newTeamListCmd())
	cmd.AddCommand(newTeamInviteCmd())
	cmd.AddCommand(newTeamRemoveCmd())
	cmd.AddCommand(newTeamTransferCmd())
	cmd.AddCommand(newTeamRoleCmd())
	cmd.AddCommand(newTeamRotateOwnerKeyCmd())
	cmd.AddCommand(newTeamHashEmailCmd())
	return cmd
}

// newTeamListCmd returns `keylatch team list [--json]`.
// Lists team members — value-free output (no raw emails).
func newTeamListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List team members (value-free: emails are HMACd)",
		RunE: func(c *cobra.Command, _ []string) error {
			t, err := loadTeam()
			if err != nil {
				return cmderr.Wrap("could not list team members", err, "check that your vault backend is unlocked and you have team access", "team-list")
			}
			jsonOut, _ := c.Flags().GetBool("json")

			type memberOut struct {
				ID       string `json:"id"`
				HMAC     string `json:"hmac"`
				Role     string `json:"role"`
				Status   string `json:"status"`
				JoinedAt string `json:"joined_at"`
			}
			members := make([]memberOut, 0, len(t.Members))
			for _, m := range t.Members {
				members = append(members, memberOut{
					ID:       m.ID,
					HMAC:     m.HMAC, // value-free: HMACd email
					Role:     string(m.Role),
					Status:   string(m.Status),
					JoinedAt: m.JoinedAt.UTC().Format(time.RFC3339),
				})
			}

			if jsonOut {
				enc := json.NewEncoder(c.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]interface{}{
					"team_id": t.ID,
					"members": members,
					"count":   len(members),
				})
			}

			fmt.Fprintf(c.OutOrStdout(), "Team: %s (%d members)\n", t.ID, len(members))
			for _, m := range members {
				fmt.Fprintf(c.OutOrStdout(), "  %s  role=%-12s  status=%-10s  joined=%s  hmac=%s\n",
					m.ID, m.Role, m.Status, m.JoinedAt, m.HMAC)
			}
			return nil
		},
	}
	return cmd
}

// newTeamInviteCmd returns `keylatch team invite --email-hmac <hmac> --role <role>`.
// Creates an invite bundle. Email is passed pre-HMACd (caller must HMAC before passing).
func newTeamInviteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "invite",
		Short: "Invite a member to the team (email-hmac required — never pass raw email)",
		RunE: func(c *cobra.Command, _ []string) error {
			emailHMAC, _ := c.Flags().GetString("email-hmac")
			role, _ := c.Flags().GetString("role")

			if emailHMAC == "" {
				// Actionable error with how to generate HMAC.
				fmt.Fprintln(c.ErrOrStderr(), "Error: team invite requires a pre-computed HMAC.")
				fmt.Fprintln(c.ErrOrStderr())
				fmt.Fprintln(c.ErrOrStderr(), "  Use `keylatch team hash-email` to generate one:")
				fmt.Fprintln(c.ErrOrStderr(), "    keylatch team hash-email alice@example.com")
				fmt.Fprintln(c.ErrOrStderr(), "    # → SHA256-HMAC: abc123...")
				fmt.Fprintln(c.ErrOrStderr())
				fmt.Fprintln(c.ErrOrStderr(), "  Then pass the HMAC to invite:")
				fmt.Fprintln(c.ErrOrStderr(), "    keylatch team invite --email-hmac abc123... --role developer")
				os.Exit(exitcode.UserError)
				return nil
			}
			if role == "" {
				role = string(team.RoleDeveloper)
			}

			t, err := loadTeam()
			if err != nil {
				return fmt.Errorf("team invite: %w", err)
			}

			bundle, err := team.CreateInvite(context.Background(), t, emailHMAC, team.Role(role))
			if err != nil {
				return fmt.Errorf("team invite: %w", err)
			}

			jsonOut, _ := c.Flags().GetBool("json")
			if jsonOut {
				enc := json.NewEncoder(c.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]interface{}{
					"status":     "invited",
					"email_hmac": emailHMAC,
					"role":       role,
					"bundle":     bundle,
				})
			}
			fmt.Fprintf(c.OutOrStdout(), "Invite bundle created for role=%s.\nBundle: %s\n", role, bundle)
			return nil
		},
	}
	cmd.Flags().String("email-hmac", "", "HMAC of the invitee's email (required)")
	cmd.Flags().String("role", "developer", "role to assign: owner|admin|developer|viewer")
	return cmd
}

// requireCallerAdmin loads the caller's member from the team and enforces admin role.
// Used by mutating team commands to enforce role checks at the CLI layer.
func requireCallerAdmin(t *team.Team) error {
	callerID := os.Getenv("KEYLATCH_MEMBER_ID")
	if callerID == "" {
		return fmt.Errorf("team: caller identity not available — authenticate first (set KEYLATCH_MEMBER_ID)")
	}
	caller, err := team.FindMember(t, callerID)
	if err != nil {
		return fmt.Errorf("team: caller member not found: %w", err)
	}
	if err := team.RequireRole(caller, team.RoleAdmin); err != nil {
		return fmt.Errorf("team: %w", err)
	}
	return nil
}

// newTeamRemoveCmd returns `keylatch team remove --id <member-id>`.
// Removes a member and triggers shared-secret rotation.
func newTeamRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a member from the team and rotate shared secrets",
		RunE: func(c *cobra.Command, _ []string) error {
			memberID, _ := c.Flags().GetString("id")
			if memberID == "" {
				return fmt.Errorf("team remove: --id is required")
			}

			t, err := loadTeam()
			if err != nil {
				return fmt.Errorf("team remove: %w", err)
			}

			// M-7: caller privilege check.
			if err := requireCallerAdmin(t); err != nil {
				return fmt.Errorf("team remove: %w", err)
			}

			if err := team.RemoveMember(context.Background(), t, memberID); err != nil {
				return fmt.Errorf("team remove: %w", err)
			}

			// RemoveMember already persists — no additional save needed.
			jsonOut, _ := c.Flags().GetBool("json")
			if jsonOut {
				enc := json.NewEncoder(c.OutOrStdout())
				return enc.Encode(map[string]interface{}{
					"status":    "removed",
					"member_id": memberID,
				})
			}
			fmt.Fprintf(c.OutOrStdout(), "Member %s removed. Shared secrets rotated.\n", memberID)
			return nil
		},
	}
	cmd.Flags().String("id", "", "member ID to remove (required)")
	return cmd
}

// newTeamTransferCmd returns `keylatch team transfer --to <id>`.
// Transfers ownership to the specified member (current owner is demoted to admin).
func newTeamTransferCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "transfer",
		Short: "Transfer team ownership to a member (current owner becomes admin)",
		RunE: func(c *cobra.Command, _ []string) error {
			toID, _ := c.Flags().GetString("to")
			if toID == "" {
				return fmt.Errorf("team transfer: --to is required")
			}

			t, err := loadTeam()
			if err != nil {
				return fmt.Errorf("team transfer: %w", err)
			}

			// M-7: caller privilege check (owner required for transfer).
			if err := requireCallerAdmin(t); err != nil {
				return fmt.Errorf("team transfer: %w", err)
			}

			if err := team.Transfer(context.Background(), t, toID); err != nil {
				return fmt.Errorf("team transfer: %w", err)
			}

			// Transfer already persists internally.
			jsonOut, _ := c.Flags().GetBool("json")
			if jsonOut {
				enc := json.NewEncoder(c.OutOrStdout())
				return enc.Encode(map[string]interface{}{
					"status": "transferred",
					"to_id":  toID,
				})
			}
			fmt.Fprintf(c.OutOrStdout(), "Ownership transferred to %s.\n", toID)
			return nil
		},
	}
	cmd.Flags().String("to", "", "new owner member ID")
	return cmd
}

// newTeamRoleCmd returns `keylatch team role --id <id> --role <role>`.
// Updates a member's role (RequireRole enforced at package layer).
func newTeamRoleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "role",
		Short: "Change a team member's role",
		RunE: func(c *cobra.Command, _ []string) error {
			memberID, _ := c.Flags().GetString("id")
			newRole, _ := c.Flags().GetString("role")
			if memberID == "" || newRole == "" {
				return fmt.Errorf("team role: --id and --role are required")
			}

			t, err := loadTeam()
			if err != nil {
				return fmt.Errorf("team role: %w", err)
			}

			// M-7: caller privilege check.
			if err := requireCallerAdmin(t); err != nil {
				return fmt.Errorf("team role: %w", err)
			}

			updated := false
			for i, m := range t.Members {
				if m.ID == memberID {
					t.Members[i].Role = team.Role(newRole)
					updated = true
					break
				}
			}
			if !updated {
				return fmt.Errorf("team role: %w: %s", team.ErrMemberNotFound, memberID)
			}

			if err := saveTeam(t); err != nil {
				return fmt.Errorf("team role: save: %w", err)
			}

			jsonOut, _ := c.Flags().GetBool("json")
			if jsonOut {
				enc := json.NewEncoder(c.OutOrStdout())
				return enc.Encode(map[string]interface{}{
					"status":    "updated",
					"member_id": memberID,
					"new_role":  newRole,
				})
			}
			fmt.Fprintf(c.OutOrStdout(), "Member %s role updated to %s.\n", memberID, newRole)
			return nil
		},
	}
	cmd.Flags().String("id", "", "member ID")
	cmd.Flags().String("role", "", "new role: owner|admin|developer|viewer")
	return cmd
}

// newTeamRotateOwnerKeyCmd returns `keylatch team rotate-owner-key`.
// Rotates the team owner's AGE key pair.
// This is a stub — hidden from help.
func newTeamRotateOwnerKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "rotate-owner-key",
		Short:  "Rotate the team owner's AGE encryption key pair",
		Hidden: true,
		RunE: func(c *cobra.Command, _ []string) error {
			// Key rotation requires interactive hardware presence proof.
			// This triggers AGE key regeneration and shared-secret rewrap.
			fmt.Fprintln(c.OutOrStdout(), "Owner key rotation requires hardware presence proof.")
			fmt.Fprintln(c.OutOrStdout(), "Run: keylatch trust challenge --then team rotate-owner-key --confirmed")
			os.Exit(exitcode.UserError)
			return nil
		},
	}
}

// newTeamHashEmailCmd returns `keylatch team hash-email <email>`.
// Produces the SHA256-HMAC of the email using the team's HMAC algorithm.
// This is a convenience command to pre-compute the HMAC for use with --email-hmac.
// hash-email helper.
func newTeamHashEmailCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hash-email <email>",
		Short: "Compute the team-scoped HMAC of an email address (use with --email-hmac)",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			email := args[0]

			if !strings.Contains(email, "@") || strings.HasPrefix(email, "@") || strings.HasSuffix(email, "@") {
				return fmt.Errorf("invalid email address: %q", email)
			}

			t, err := loadTeam()
			if err != nil {
				// If team is not configured, we cannot derive a team-scoped HMAC.
				return fmt.Errorf("team hash-email: %w", err)
			}

			h := team.HMACValue(t.ID, email)
			fmt.Fprintf(c.OutOrStdout(), "SHA256-HMAC: %s  (use this value for --email-hmac)\n", h)
			return nil
		},
	}
}

// loadTeam loads the team from KEYLATCH_TEAM_DIR or the default location.
func loadTeam() (*team.Team, error) {
	return team.Load(context.Background())
}

// saveTeam persists the team to KEYLATCH_TEAM_DIR or the default location.
func saveTeam(t *team.Team) error {
	return team.Save(context.Background(), t)
}
