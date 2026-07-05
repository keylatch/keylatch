package cli

// security_cmd.go implements `keylatch security` — §4.5 security invariants.

import (
	"fmt"

	"github.com/spf13/cobra"
)

// securityInvariants is the user-facing copy of the five security invariants.
// See docs/security/invariants.md for the security-invariant catalog.
const securityInvariants = `Keylatch security model:

  * Your secrets never touch agent memory
  * Every secret use is logged
  * Revoking access is instant
  * Approvals expire automatically
  * No secret leaves your machine without your say-so

Run ` + "`keylatch audit tail`" + ` to watch the log live.
Run ` + "`keylatch doctor`" + ` for a system health check.
`

// newSecurityCmd returns the `keylatch security` command.
// §4.5: print the five user-facing security invariants as a formatted block.
func newSecurityCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "security",
		Short: "Show the Keylatch security model and invariants",
		Long: `Display the five user-facing security invariants that Keylatch enforces.

These invariants describe what Keylatch guarantees about your credentials at
runtime. For a detailed threat model see docs/security/threat-model.md.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprint(cmd.OutOrStdout(), securityInvariants)
			return nil
		},
	}
}
