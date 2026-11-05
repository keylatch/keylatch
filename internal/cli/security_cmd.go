package cli

// security_cmd.go implements `keylatch security` — §4.5 security invariants.

import (
	"fmt"

	"github.com/spf13/cobra"
)

// securityInvariants is the user-facing copy of the five security invariants.
// See docs/security/invariants.md for the security-invariant catalog.
const securityInvariants = `Keylatch security model:

  * Agents use secrets only through brokered actions
  * Every secret use is logged
  * Revoking access is instant
  * Approvals expire automatically
  * The raw credential is sent only to the allowlisted provider endpoint

In-user mode is defense in depth, not a boundary against an agent running as
your own user; docs/security/threat-model.md says what each mode protects.

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
