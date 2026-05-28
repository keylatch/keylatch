package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/vault"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
	"github.com/spf13/cobra"
)

// newVersionsCmd returns the `versions` subcommand.
// Security invariant S4-1: MUST NOT print values or call vault.Get.
// Canary invariant: output must not contain KEYLATCH_CANARY_PHASE4_VERSIONS_0xDEADBEEF.
func newVersionsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "versions <path>",
		Short: "List version history for a credential",
		Long: `Show the version history for a credential path.

This command reads only metadata — it never decrypts credential values.

State column:
  live      — version is accessible
  deleted   — soft-deleted (evicted by MaxVersions policy)
  destroyed — permanently destroyed by destroy-version`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()
			cfg := loadCLIConfig(c)
			env := llmcontext.DefaultLookup

			path := args[0]

			// Security invariant S4-1: GetMeta never decrypts values.
			m, err := vault.GetMeta(ctx, path, cfg, env)
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "[keylatch] error: %v\n", err)
				os.Exit(exitcode.OperationFailed)
			}

			printVersionsTable(c, m)
			return nil
		},
	}
}

// printVersionsTable prints the version history table to the command's stdout.
func printVersionsTable(c *cobra.Command, m vmeta.Meta) {
	w := c.OutOrStdout()

	fmt.Fprintf(w, "%-4s  %-10s  %-30s  %-30s  %s\n",
		"VER", "STATE", "CREATED_AT", "EXPIRES_AT", "CREATED_BY")
	fmt.Fprintf(w, "%s\n",
		"──────────────────────────────────────────────────────────────────────────────────────────")

	for _, vm := range m.Versions {
		state := versionState(vm)
		current := ""
		if vm.Version == m.CurrentVersion {
			current = " *"
		}

		createdAt := vm.CreatedAt.Format(time.RFC3339)
		expiresAt := "—"
		if vm.ExpiresAt != nil {
			expiresAt = vm.ExpiresAt.Format(time.RFC3339)
		}

		fmt.Fprintf(w, "%-4d  %-10s  %-30s  %-30s  %s%s\n",
			vm.Version, state, createdAt, expiresAt, vm.CreatedBy, current)
	}

	fmt.Fprintf(w, "\nCurrent version: %d  |  Backend: %s  |  Accessor: %s\n",
		m.CurrentVersion, m.Backend, truncateAccessor(string(m.Accessor), 16))
}

// versionState returns the display state for a VersionMeta.
func versionState(vm vmeta.VersionMeta) string {
	if vm.DestroyedAt != nil {
		return "destroyed"
	}
	if vm.DeletedAt != nil {
		return "deleted"
	}
	return "live"
}
