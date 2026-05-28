package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/vault"
	"github.com/keylatch/keylatch/internal/vault/expiry"
	"github.com/spf13/cobra"
)

// ErrExpiredCredentials is returned (not os.Exit) when check-expiry finds expired entries.
// main.go translates any RunE error to exit code 1 (UserError).
var ErrExpiredCredentials = errors.New("expired credentials detected")

// checkExpiryEntry is the JSON output shape for --json mode.
type checkExpiryEntry struct {
	Path          string `json:"path"`
	Accessor      string `json:"accessor"`
	ExpiresAt     string `json:"expires_at,omitempty"`
	DaysRemaining int    `json:"days_remaining"`
	Status        string `json:"status"`
}

// newPhase4CheckExpiryCmd returns the Phase 4 `check-expiry` command.
// Security invariant S4-1: MUST NOT call vault.Get or backend.Get.
// Canary invariant: output must not contain KEYLATCH_CANARY_PHASE4_EXPIRY_0xDEADBEEF.
func newPhase4CheckExpiryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "check-expiry [--days N] [--json]",
		Short:         "Check credential expiry status",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `List credentials that are expired or expiring within the threshold.

This command reads only metadata — it never decrypts credential values.

Exit code 1 if any credentials are expired; 0 otherwise.`,
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()
			cfg := loadCLIConfig(c)
			env := llmcontext.DefaultLookup

			days, _ := c.Flags().GetInt("days")
			jsonOutput, _ := c.Flags().GetBool("json")

			if days <= 0 {
				days = expiry.DefaultWarnDays
			}

			// Security invariant S4-1: ListMeta never decrypts values.
			metas, err := vault.ListMeta(ctx, "", cfg, env)
			if err != nil {
				return fmt.Errorf("[keylatch] error: %w (exit %d)", err, exitcode.OperationFailed)
			}

			now := time.Now()
			var entries []checkExpiryEntry
			hasExpired := false

			for _, m := range metas {
				status := expiry.Status(m, now, days)
				if status == "ok" {
					continue
				}

				daysLeft := expiry.DaysRemaining(m, now)
				entry := checkExpiryEntry{
					Path:          m.Path,
					Accessor:      truncateAccessor(string(m.Accessor), 12),
					DaysRemaining: daysLeft,
					Status:        status,
				}
				if m.ExpiresAt != nil {
					entry.ExpiresAt = m.ExpiresAt.Format(time.RFC3339)
				}
				entries = append(entries, entry)

				if status == "expired" {
					hasExpired = true
				}
			}

			if jsonOutput {
				if err := outputCheckExpiryJSON(c, entries); err != nil {
					return fmt.Errorf("[keylatch] error: %w (exit %d)", err, exitcode.OperationFailed)
				}
			} else {
				outputCheckExpiryTable(c, entries)
			}

			if hasExpired {
				return ErrExpiredCredentials
			}
			return nil
		},
	}

	cmd.Flags().Int("days", expiry.DefaultWarnDays, "warn threshold in days")
	cmd.Flags().Bool("json", false, "output as JSON array")

	return cmd
}

// outputCheckExpiryTable prints a human-readable table to stdout.
func outputCheckExpiryTable(c *cobra.Command, entries []checkExpiryEntry) {
	if len(entries) == 0 {
		fmt.Fprintln(c.OutOrStdout(), "No expiring or expired credentials.")
		return
	}
	fmt.Fprintf(c.OutOrStdout(), "%-40s  %-12s  %-25s  %5s  %s\n",
		"PATH", "ACCESSOR", "EXPIRES_AT", "DAYS", "STATUS")
	fmt.Fprintf(c.OutOrStdout(), "%s\n", "────────────────────────────────────────────────────────────────────────────────────────────────")
	for _, e := range entries {
		expiresAt := e.ExpiresAt
		if expiresAt == "" {
			expiresAt = "—"
		}
		fmt.Fprintf(c.OutOrStdout(), "%-40s  %-12s  %-25s  %5d  %s\n",
			e.Path, e.Accessor, expiresAt, e.DaysRemaining, e.Status)
	}
}

// outputCheckExpiryJSON marshals entries as a JSON array to stdout.
func outputCheckExpiryJSON(c *cobra.Command, entries []checkExpiryEntry) error {
	if entries == nil {
		entries = []checkExpiryEntry{}
	}
	enc := json.NewEncoder(c.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

// truncateAccessor truncates an accessor string to n characters for display.
func truncateAccessor(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
