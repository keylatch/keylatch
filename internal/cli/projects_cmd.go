// Package cli — Phase 8 projects subcommands.
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

// projectEntry is a persisted project record.
type projectEntry struct {
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// newProjectsCmd returns the `keylatch projects` group command.
func newProjectsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "projects",
		Short: "Manage projects",
	}
	cmd.AddCommand(newProjectsListCmd())
	cmd.AddCommand(newProjectsCreateCmd())
	cmd.AddCommand(newProjectsDeleteCmd())
	return cmd
}

func newProjectsListCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List projects",
		RunE: func(c *cobra.Command, _ []string) error {
			projects, err := loadProjects()
			if err != nil {
				return err
			}
			if jsonOut {
				b, _ := json.MarshalIndent(projects, "", "  ")
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}
			w := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tDESCRIPTION\tCREATED")
			for _, p := range projects {
				fmt.Fprintf(w, "%s\t%s\t%s\n", p.Name, p.Description, p.CreatedAt.UTC().Format(time.RFC3339))
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output as JSON")
	return cmd
}

func newProjectsCreateCmd() *cobra.Command {
	var description string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a project",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			name := args[0]
			projects, err := loadProjects()
			if err != nil {
				return err
			}
			for _, p := range projects {
				if p.Name == name {
					return fmt.Errorf("project %q already exists", name)
				}
			}
			projects = append(projects, projectEntry{
				Name:        name,
				Description: description,
				CreatedAt:   time.Now().UTC(),
			})
			if err := saveProjects(projects); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "project %q created\n", name)
			return nil
		},
	}
	cmd.Flags().StringVar(&description, "description", "", "project description")
	return cmd
}

func newProjectsDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a project",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			name := args[0]
			projects, err := loadProjects()
			if err != nil {
				return err
			}
			original := len(projects)
			filtered := projects[:0]
			for _, p := range projects {
				if p.Name != name {
					filtered = append(filtered, p)
				}
			}
			if len(filtered) == original {
				return fmt.Errorf("project %q not found", name)
			}
			if err := saveProjects(filtered); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "project %q deleted\n", name)
			return nil
		},
	}
}

func loadProjects() ([]projectEntry, error) {
	p := paths.Projects(llmcontext.DefaultLookup)
	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var projects []projectEntry
	if err := json.Unmarshal(data, &projects); err != nil {
		return nil, err
	}
	return projects, nil
}

func saveProjects(projects []projectEntry) error {
	p := paths.Projects(llmcontext.DefaultLookup)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	if projects == nil {
		projects = []projectEntry{}
	}
	b, err := json.MarshalIndent(projects, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return err
	}
	return os.Chmod(p, 0o600)
}
