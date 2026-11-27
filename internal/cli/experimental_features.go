//go:build experimental

package cli

import (
	"github.com/spf13/cobra"

	cmdtrust "github.com/keylatch/keylatch/internal/cmd/trust"
	_ "github.com/keylatch/keylatch/internal/trust/all"
)

// registerExperimentalFeatures adds the unfinished team, trust and
// shared-secret commands. They exist only in builds with the experimental tag.
func registerExperimentalFeatures(root *cobra.Command) {
	root.AddGroup(&cobra.Group{ID: "team", Title: "Team"})
	addCmd(root, newTeamCmd(), "team")
	cmdtrust.RegisterCommands(root, "advanced")
}
