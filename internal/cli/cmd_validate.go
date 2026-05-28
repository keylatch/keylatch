package cli

import (
	"fmt"
	"os"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/validate"
	"github.com/spf13/cobra"
)

// newPhase3ValidateCmd returns the Phase 3 `validate` command.
func newPhase3ValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate all connections against their provider schemas",
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()
			cfg := loadCLIConfig(c)
			store := newDispatchedStore(cfg, llmcontext.DefaultLookup)

			namespace, _ := c.Flags().GetString("namespace")
			strict, _ := c.Flags().GetBool("strict")

			issues, err := validate.ValidateStore(ctx, validate.ValidateOptions{
				Namespace: namespace,
				Strict:    strict,
			}, store)
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				os.Exit(exitcode.OperationFailed)
			}

			errorCount := 0
			for _, issue := range issues {
				prefix := "[WARN]"
				if issue.IsError {
					prefix = "[ERROR]"
					errorCount++
				}
				fmt.Fprintf(c.OutOrStdout(), "%s %s: %s\n", prefix, issue.Field, issue.Message)
			}

			fmt.Fprintf(c.OutOrStdout(), "\n%d issue(s) found (%d error(s))\n",
				len(issues), errorCount)

			if errorCount > 0 {
				os.Exit(exitcode.UserError)
			}
			return nil
		},
	}
	cmd.Flags().String("namespace", "default", "vault namespace")
	cmd.Flags().Bool("strict", false, "treat unknown config keys as errors")
	return cmd
}
