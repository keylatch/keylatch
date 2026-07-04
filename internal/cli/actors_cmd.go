// Package cli — actors subcommands.
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
	"github.com/keylatch/keylatch/internal/policy/actor"
	"github.com/spf13/cobra"
)

// actorEntry is a persisted actor record.
type actorEntry struct {
	Name      string    `json:"name"`
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// newActorsCmd returns the `keylatch actors` group command.
func newActorsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "actors",
		Short: "Manage actor identities (value-free)",
	}
	cmd.AddCommand(newActorsListCmd())
	cmd.AddCommand(newActorsGetDefaultCmd())
	cmd.AddCommand(newActorsCreateCmd())
	cmd.AddCommand(newActorsDeleteCmd())
	cmd.AddCommand(newActorsRenameCmd())
	return cmd
}

func newActorsListCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List registered actors",
		RunE: func(c *cobra.Command, _ []string) error {
			actors, err := loadActors()
			if err != nil {
				return err
			}
			if jsonOut {
				b, _ := json.MarshalIndent(actors, "", "  ")
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}
			w := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tNOTE\tCREATED")
			for _, a := range actors {
				fmt.Fprintf(w, "%s\t%s\t%s\n", a.Name, a.Note, a.CreatedAt.UTC().Format(time.RFC3339))
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output as JSON")
	return cmd
}

func newActorsGetDefaultCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get-default",
		Short: "Print the inferred actor for the current environment",
		RunE: func(c *cobra.Command, _ []string) error {
			a := actor.Infer(llmcontext.DefaultLookup)
			fmt.Fprintf(c.OutOrStdout(), "%s (source: %s)\n", a.Name, a.Source)
			return nil
		},
	}
}

func newActorsCreateCmd() *cobra.Command {
	var note string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Register a named actor",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			name := args[0]
			if err := actor.Validate(name); err != nil {
				return err
			}
			actors, err := loadActors()
			if err != nil {
				return err
			}
			for _, a := range actors {
				if a.Name == name {
					return fmt.Errorf("actor %q already exists", name)
				}
			}
			actors = append(actors, actorEntry{
				Name:      name,
				Note:      note,
				CreatedAt: time.Now().UTC(),
			})
			if err := saveActors(actors); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "actor %q created\n", name)
			return nil
		},
	}
	cmd.Flags().StringVar(&note, "note", "", "free-text note")
	return cmd
}

func newActorsDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a registered actor",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			name := args[0]
			actors, err := loadActors()
			if err != nil {
				return err
			}
			original := len(actors)
			filtered := actors[:0]
			for _, a := range actors {
				if a.Name != name {
					filtered = append(filtered, a)
				}
			}
			if len(filtered) == original {
				return fmt.Errorf("actor %q not found", name)
			}
			if err := saveActors(filtered); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "actor %q deleted\n", name)
			return nil
		},
	}
}

func newActorsRenameCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rename <old> <new>",
		Short: "Rename a registered actor",
		Args:  cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			old, newName := args[0], args[1]
			if err := actor.Validate(newName); err != nil {
				return err
			}
			actors, err := loadActors()
			if err != nil {
				return err
			}
			found := false
			for i := range actors {
				if actors[i].Name == old {
					actors[i].Name = newName
					found = true
				}
			}
			if !found {
				return fmt.Errorf("actor %q not found", old)
			}
			if err := saveActors(actors); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "actor %q renamed to %q\n", old, newName)
			return nil
		},
	}
}

func loadActors() ([]actorEntry, error) {
	p := paths.Actors(llmcontext.DefaultLookup)
	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var actors []actorEntry
	if err := json.Unmarshal(data, &actors); err != nil {
		return nil, err
	}
	return actors, nil
}

func saveActors(actors []actorEntry) error {
	p := paths.Actors(llmcontext.DefaultLookup)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	if actors == nil {
		actors = []actorEntry{}
	}
	b, err := json.MarshalIndent(actors, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return err
	}
	return os.Chmod(p, 0o600)
}
