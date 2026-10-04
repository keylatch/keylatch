package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/keylatch/keylatch/internal/bootstrap"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/spf13/cobra"
)

// newBootstrapCmd returns the `bootstrap` subcommand.
// NOT guarded by GuardLLMSession — bootstrap is value-free.
func newBootstrapCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Initialize the keylatch configuration directory",
		Long: `Bootstrap creates ~/.keylatch/ (0700), ~/.keylatch/vault/ (0700),
~/.keylatch/audit.log (0600), and ~/.keylatch/config.json (0600) with
safe defaults. Running bootstrap a second time is a no-op unless --force
is passed, which destroys and re-creates the cryptographic keyring after
an interactive confirmation prompt. KEYLATCH_PASSPHRASE has no effect.

For the file backend the vault identity, from which the key-encryption key
is derived, is stored in the OS keyring (macOS Keychain or a freedesktop
Secret Service). Without a usable keyring bootstrap fails unless
--insecure-file-kek (or KEYLATCH_INSECURE_FILE_KEK=1) is given, which keeps
the identity in a plaintext file next to the vault. Re-running bootstrap
moves a plaintext identity from an older install into the keyring.`,
		RunE: func(c *cobra.Command, _ []string) error {
			dryRun, _ := c.Flags().GetBool("dry-run")
			jsonOut, _ := c.Flags().GetBool("json")
			backend, _ := c.Flags().GetString("backend")
			force, _ := c.Flags().GetBool("force")
			insecureFileKEK, _ := c.Flags().GetBool("insecure-file-kek")

			// --force requires explicit user confirmation before proceeding.
			if force && !dryRun {
				fmt.Fprint(c.OutOrStdout(), "Destroy existing keyring and re-initialize? [y/N]: ")
				scanner := bufio.NewScanner(c.InOrStdin())
				scanner.Scan()
				if err := scanner.Err(); err != nil {
					return fmt.Errorf("--force: read confirmation: %w", err)
				}
				answer := strings.TrimSpace(scanner.Text())
				if !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
					fmt.Fprintln(c.OutOrStdout(), "Aborted.")
					return nil
				}
			}

			plan, err := bootstrap.Run(c.Context(), bootstrap.Options{
				DryRun:          dryRun,
				JSON:            jsonOut,
				Backend:         backend,
				Env:             llmcontext.DefaultLookup,
				Force:           force,
				Confirm:         true, // CLI handles confirmation above
				InsecureFileKEK: insecureFileKEK,
			})
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "bootstrap: %v\n", err)
				os.Exit(1)
			}

			if jsonOut {
				b, marshalErr := bootstrap.RenderJSON(plan)
				if marshalErr != nil {
					fmt.Fprintf(c.ErrOrStderr(), "bootstrap: marshal: %v\n", marshalErr)
					os.Exit(1)
				}
				fmt.Fprintln(c.OutOrStdout(), string(b))
			} else {
				fmt.Fprint(c.OutOrStdout(), bootstrap.RenderText(plan))
			}
			return nil
		},
	}

	cmd.Flags().Bool("dry-run", false, "plan steps without writing any files")
	cmd.Flags().Bool("json", false, "output plan as JSON")
	cmd.Flags().String("backend", "file", "credential backend: file, keychain (macOS only), op, bw")
	cmd.Flags().Bool("force", false, "destroy existing keyring and re-initialize (prompts for confirmation)")
	cmd.Flags().Bool("insecure-file-kek", false, "store the vault key in a plaintext file next to the vault when no OS keyring is available (any process running as you can decrypt the vault)")

	return cmd
}

// bootstrapPlanJSON is the JSON shape returned for --json output. Exported for
// use in e2e tests.
//
//nolint:unused // used by ParseBootstrapPlan below and in integration tests
type bootstrapPlanJSON struct {
	Steps    []bootstrap.PlanStep `json:"Steps"`
	Warnings []string             `json:"Warnings"`
}

// ParseBootstrapPlan parses bootstrap --json output for use in tests.
func ParseBootstrapPlan(data []byte) (bootstrap.Plan, error) {
	var p bootstrap.Plan
	if err := json.Unmarshal(data, &p); err != nil {
		return bootstrap.Plan{}, err
	}
	return p, nil
}
