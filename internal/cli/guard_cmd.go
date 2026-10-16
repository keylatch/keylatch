package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/guard/hook"
	"github.com/spf13/cobra"
)

// newGuardCmd returns `keylatch guard`, the commands an agent harness runs as
// hooks.
func newGuardCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "guard",
		Short: "Run an agent tool-call guard",
		// A hook runs before every tool call: it must not start the registry
		// or any other subsystem the root command initialises.
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
	}
	cmd.AddCommand(newGuardHookCmd())
	return cmd
}

func newGuardHookCmd() *cobra.Command {
	var harness string
	cmd := &cobra.Command{
		Use:   "hook --harness claude-code",
		Short: "Decide one pre-tool call read from stdin",
		Long: `Reads the harness's pre-tool JSON from stdin and denies the call (the
harness's deny JSON on stdout, a reason on stderr, exit 2) when it would read a
Keylatch or credential location, dump the environment, call a secret manager,
or change the harness settings. Shell commands are parsed, not pattern-matched;
input the guard cannot parse is denied. --harness picks the payload and the
deny contract: Antigravity documents decisions as stdout JSON only, so it
denies with exit 0 and that JSON. An allowed call prints nothing (Cursor and
Gemini CLI expect an explicit allow) and exits 0.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !slices.Contains(hook.Harnesses(), harness) {
				fmt.Fprintf(cmd.ErrOrStderr(), "[hook/keylatch] Blocked: unsupported harness %q (supported: %s)\n", harness, strings.Join(hook.Harnesses(), ", "))
				return &CLIError{Class: "SecurityBlock", Code: exitcode.SecurityBlock, Quiet: true}
			}
			if code := hook.RunFor(harness, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), hook.DefaultEnv()); code != 0 {
				return &CLIError{Class: "SecurityBlock", Code: code, Quiet: true}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&harness, "harness", "", "agent harness whose payload and deny contract to use ("+strings.Join(hook.Harnesses(), ", ")+")")
	return cmd
}
