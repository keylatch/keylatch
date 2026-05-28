// Package cli — Phase 8 grant subcommands.
package cli

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/keylatch/keylatch/internal/grant"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/spf13/cobra"
)

// newGrantCmd returns the `keylatch grant` group command.
func newGrantCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "grant",
		Short: "Manage short-lived capability grants",
	}
	cmd.AddCommand(newGrantCreateCmd())
	cmd.AddCommand(newGrantListCmd())
	cmd.AddCommand(newGrantRevokeCmd())
	return cmd
}

// newGrantCreateCmd creates a new grant.
func newGrantCreateCmd() *cobra.Command {
	var (
		actorName  string
		capability string
		ttlStr     string
		cmdGlob    string
		cwdGlob    string
		maxUses    int
	)
	cmd := &cobra.Command{
		Use:   "create <connection>",
		Short: "Issue a new short-lived grant",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			connection := args[0]
			env := llmcontext.DefaultLookup

			if actorName == "" {
				return fmt.Errorf("--actor is required")
			}

			ttl := 1 * time.Hour
			if ttlStr != "" {
				d, err := time.ParseDuration(ttlStr)
				if err != nil {
					return fmt.Errorf("invalid --ttl: %w", err)
				}
				ttl = d
			}

			spec := grant.GrantSpec{
				Actor:      actorName,
				Connection: connection,
				Capability: capability,
				Command:    cmdGlob,
				CWD:        cwdGlob,
				TTL:        ttl,
				MaxUses:    maxUses,
			}

			g, err := grant.Create(context.Background(), spec, env)
			if err != nil {
				return fmt.Errorf("grant create: %w", err)
			}

			fmt.Fprintf(c.OutOrStdout(), "grant id:      %s\n", g.ID)
			fmt.Fprintf(c.OutOrStdout(), "expires at:    %s\n", g.ExpiresAt.UTC().Format(time.RFC3339))
			if maxUses > 0 {
				fmt.Fprintf(c.OutOrStdout(), "max uses:      %d\n", g.MaxUses)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&actorName, "actor", "", "actor name (required)")
	cmd.Flags().StringVar(&capability, "capability", "inject", "capability to grant")
	cmd.Flags().StringVar(&ttlStr, "ttl", "1h", "time-to-live (e.g. 30m, 2h)")
	cmd.Flags().StringVar(&cmdGlob, "command", "", "command glob pattern")
	cmd.Flags().StringVar(&cwdGlob, "cwd", "", "CWD glob pattern")
	cmd.Flags().IntVar(&maxUses, "max-uses", 0, "maximum number of uses (0 = unlimited)")
	return cmd
}

// newGrantListCmd lists active grants value-free.
func newGrantListCmd() *cobra.Command {
	var (
		jsonOut        bool
		includeExpired bool
		includeRevoked bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List grants (value-free)",
		RunE: func(c *cobra.Command, _ []string) error {
			env := llmcontext.DefaultLookup
			grantPath := paths.Grants(env)

			gs, err := grant.List(context.Background(), grantPath, grant.ListOpts{
				IncludeExpired: includeExpired,
				IncludeRevoked: includeRevoked,
			})
			if err != nil {
				return fmt.Errorf("grant list: %w", err)
			}
			if gs == nil {
				gs = []grant.Grant{}
			}

			if jsonOut {
				type jsonGrant struct {
					ID         string `json:"id"`
					Actor      string `json:"actor"`
					Connection string `json:"connection"`
					Capability string `json:"capability"`
					ExpiresAt  string `json:"expires_at"`
					Revoked    bool   `json:"revoked,omitempty"`
					MaxUses    int    `json:"max_uses,omitempty"`
				}
				out := make([]jsonGrant, 0, len(gs))
				for _, g := range gs {
					out = append(out, jsonGrant{
						ID:         g.ID,
						Actor:      g.Actor,
						Connection: g.Connection,
						Capability: g.Capability,
						ExpiresAt:  g.ExpiresAt.UTC().Format(time.RFC3339),
						Revoked:    g.Revoked,
						MaxUses:    g.MaxUses,
					})
				}
				b, _ := json.MarshalIndent(out, "", "  ")
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}

			w := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tACTOR\tCONNECTION\tCAPABILITY\tEXPIRES")
			for _, g := range gs {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					g.ID, g.Actor, g.Connection, g.Capability,
					g.ExpiresAt.UTC().Format(time.RFC3339),
				)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output as JSON")
	cmd.Flags().BoolVar(&includeExpired, "include-expired", false, "include expired grants")
	cmd.Flags().BoolVar(&includeRevoked, "include-revoked", false, "include revoked grants")
	return cmd
}

// newGrantRevokeCmd revokes a grant.
func newGrantRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <grant-id>",
		Short: "Revoke a grant (cascades to children)",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			grantID := args[0]
			env := llmcontext.DefaultLookup
			grantPath := paths.Grants(env)

			if err := grant.Revoke(context.Background(), grantPath, grantID); err != nil {
				return fmt.Errorf("grant revoke: %w", err)
			}
			fmt.Fprintf(c.OutOrStdout(), "grant %s revoked\n", grantID)
			return nil
		},
	}
}

// generateUUID generates a UUID v4.
func generateUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
