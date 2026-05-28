// Package cli — Phase 8/9 sessions subcommands (Phase 9 wire-up stub).
package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/spf13/cobra"
)

// sessionEntry is a persisted session record.
type sessionEntry struct {
	ID        string    `json:"id"`
	Actor     string    `json:"actor"`
	StartedAt time.Time `json:"started_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Active    bool      `json:"active"`
}

// newSessionsCmd returns the `keylatch sessions` group command.
func newSessionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sessions",
		Short: "Manage LLM sessions (Phase 9 stub)",
	}
	cmd.AddCommand(newSessionsListCmd())
	cmd.AddCommand(newSessionsStartCmd())
	cmd.AddCommand(newSessionsKillCmd())
	return cmd
}

func newSessionsListCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List active sessions",
		RunE: func(c *cobra.Command, _ []string) error {
			sessions, err := loadSessions()
			if err != nil {
				return err
			}
			// Filter to active only.
			var active []sessionEntry
			for _, s := range sessions {
				if s.Active {
					active = append(active, s)
				}
			}

			if jsonOut {
				if active == nil {
					active = []sessionEntry{}
				}
				b, _ := json.MarshalIndent(active, "", "  ")
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}
			w := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tACTOR\tSTARTED\tEXPIRES")
			for _, s := range active {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
					s.ID, s.Actor,
					s.StartedAt.UTC().Format(time.RFC3339),
					s.ExpiresAt.UTC().Format(time.RFC3339),
				)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output as JSON")
	return cmd
}

func newSessionsStartCmd() *cobra.Command {
	var (
		actorName string
		ttlStr    string
	)
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start a new session (Phase 9 stub — persists record only)",
		RunE: func(c *cobra.Command, _ []string) error {
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

			id, err := generateUUID()
			if err != nil {
				return err
			}

			now := time.Now().UTC()
			entry := sessionEntry{
				ID:        id,
				Actor:     actorName,
				StartedAt: now,
				ExpiresAt: now.Add(ttl),
				Active:    true,
			}

			sessions, err := loadSessions()
			if err != nil {
				return err
			}
			sessions = append(sessions, entry)
			if err := saveSessions(sessions); err != nil {
				return err
			}

			fmt.Fprintf(c.OutOrStdout(), "session id: %s\n", id)
			fmt.Fprintf(c.OutOrStdout(), "expires at: %s\n", entry.ExpiresAt.Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringVar(&actorName, "actor", "", "actor name (required)")
	cmd.Flags().StringVar(&ttlStr, "ttl", "1h", "session TTL")
	return cmd
}

func newSessionsKillCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "kill <session-id>",
		Short: "Kill (deactivate) a session",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			id := args[0]
			sessions, err := loadSessions()
			if err != nil {
				return err
			}
			found := false
			for i := range sessions {
				if sessions[i].ID == id {
					sessions[i].Active = false
					found = true
				}
			}
			if !found {
				return fmt.Errorf("session %q not found", id)
			}
			if err := saveSessions(sessions); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "session %s killed\n", id)
			return nil
		},
	}
}

func loadSessions() ([]sessionEntry, error) {
	p := paths.Sessions(llmcontext.DefaultLookup)
	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var sessions []sessionEntry
	if err := json.Unmarshal(data, &sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}

func saveSessions(sessions []sessionEntry) error {
	p := paths.Sessions(llmcontext.DefaultLookup)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	if sessions == nil {
		sessions = []sessionEntry{}
	}
	b, err := json.MarshalIndent(sessions, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return err
	}
	return os.Chmod(p, 0o600)
}
