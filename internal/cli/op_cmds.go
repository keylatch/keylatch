package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	osexec "os/exec"
	"strings"

	"golang.org/x/term"
	"io"
	"os"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/backend/op"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/spf13/cobra"
)

// RegisterOPCommands attaches op-related commands to root.
func RegisterOPCommands(root *cobra.Command) {
	root.AddCommand(newOPInitCmd())
	root.AddCommand(newOPListCmd())
	root.AddCommand(newOPParentCmd())
}

// newOPParentCmd returns the `op` command group (session orchestration: H5).
func newOPParentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "op",
		Short: "1Password session management (signin)",
	}
	cmd.AddCommand(newOPSigninCmd())
	return cmd
}

// opAccountListRunner is the subset of kexec.CommandRunner newOPSigninCmd
// needs, injectable for tests.
type opAccountListRunner interface {
	Run(ctx context.Context, name string, args []string, stdin []byte) (stdout, stderr []byte, exitCode int, err error)
}

// newOPSigninCmd returns the `op signin` command.
//
// Unlike bw unlock, op signin deliberately does NOT cache a session token.
// 1Password CLI sessions (OP_SESSION_<account>) are exported into the
// invoking shell by op's own `op signin` — a child process (keylatch) can
// never mutate its parent shell's environment, so there is no token keylatch
// could meaningfully capture and re-inject the way it does for bw's
// BW_SESSION. With desktop-app biometric integration, op authenticates
// per-command transparently (no session token at all in the traditional
// sense) — caching anything here would either be a no-op or actively wrong.
// This command is guidance-first: it tells the user the correct next step
// rather than pretending to manage a session it structurally cannot own.
func newOPSigninCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "signin",
		Short: "Check 1Password auth state and show the correct next step",
		Long: `op signin does not cache a session (see backend/op — 1Password sessions
are exported into the invoking shell by op itself and are owned by op's own
daemon/biometric integration, not keylatch). This command is guidance-first:

  1. If OP_SERVICE_ACCOUNT_TOKEN is set, that's used for all op calls — no
     signin needed; this command just confirms that and exits.
  2. Otherwise it probes "op account list" to see whether op can already
     authenticate (e.g. via Touch ID / desktop-app biometric integration).
     If so, no signin needed.
  3. Otherwise, in an interactive terminal, it hands the terminal to the
     real "op signin" so you can complete the prompt (biometric or master
     password) — you still need to "eval $(op signin)" yourself afterward;
     that step cannot be automated by a child process. Outside a terminal
     (LLM session, CI, piped stdin), it only prints this guidance and exits
     non-zero — set OP_SERVICE_ACCOUNT_TOKEN for non-interactive use.`,
		RunE: func(c *cobra.Command, args []string) error {
			return runOPSignin(c.Context(), c, llmcontext.DefaultLookup, kexec.DefaultRunner, kexec.Resolve("op"), stdinIsTTY())
		},
	}
}

// runOPSignin implements `op signin`'s guidance-first logic. All
// dependencies (env, runner, resolved binary, TTY-ness) are injected so
// tests can exercise every branch — including the interactive hand-off
// decision — without a real op CLI or a real terminal. The live
// os/exec.CommandContext hand-off (interactive branch) is exercised by
// production callers only; tests stop at the "about to hand off" branch
// using a resolvedBin that doesn't reach a real binary would panic
// exec.CommandContext at Run() time, so interactive-branch tests instead
// assert on the printed guidance and TTY gating, not on invoking a real op.
func runOPSignin(ctx context.Context, c *cobra.Command, env llmcontext.Lookup, runner opAccountListRunner, opBin string, isTTY bool) error {
	if tok := env("OP_SERVICE_ACCOUNT_TOKEN"); tok != "" {
		fmt.Fprintln(c.OutOrStdout(), "OP_SERVICE_ACCOUNT_TOKEN is set — using service-account auth, no signin needed.")
		return nil
	}

	if opBin == "" {
		fmt.Fprintf(c.ErrOrStderr(), "Error: 1Password CLI not available. Run: brew install 1password-cli\n")
		return fmt.Errorf("exit %d", exitcode.BackendUnavailable)
	}

	_, _, exitCode, runErr := runner.Run(ctx, opBin, []string{"account", "list", "--format=json"}, nil)
	if runErr == nil && exitCode == 0 {
		fmt.Fprintln(c.OutOrStdout(), "op can already authenticate (op account list succeeded) — no signin needed.")
		return nil
	}

	if !isTTY {
		fmt.Fprintln(c.ErrOrStderr(), "Error: not signed in to 1Password, and no interactive terminal available.")
		fmt.Fprintln(c.ErrOrStderr(), "  For automation: set OP_SERVICE_ACCOUNT_TOKEN.")
		fmt.Fprintln(c.ErrOrStderr(), "  Interactively: re-run this command from a terminal, or run: eval $(op signin)")
		return fmt.Errorf("exit %d", exitcode.BackendUnavailable)
	}

	if llmcontext.IsLLMSession(env) {
		fmt.Fprintln(c.ErrOrStderr(), "Error: 'op signin' is interactive-only — blocked in LLM session (exit 2)")
		fmt.Fprintln(c.ErrOrStderr(), "  For automation: set OP_SERVICE_ACCOUNT_TOKEN.")
		return fmt.Errorf("exit %d", exitcode.SecurityBlock)
	}

	fmt.Fprintln(c.OutOrStdout(), "Not signed in — handing off to `op signin`. Complete the prompt, then run:")
	fmt.Fprintln(c.OutOrStdout(), "  eval $(op signin)")
	fmt.Fprintln(c.OutOrStdout(), "(keylatch cannot export the session into your shell for you — that step is inherent to how op signin works.)")

	// Interactive passthrough, deliberately NOT via kexec.CommandRunner:
	// CommandRunner's buffered stdin-bytes/captured-stdout model cannot
	// support op signin's live biometric/master-password prompts. Direct
	// os/exec passthrough for genuinely interactive subprocesses has
	// precedent in this package (see verify_cmd.go's cosign invocation).
	//nolint:gosec // G204: opBin is resolved via kexec.Resolve (PATH lookup), not user input
	signinCmd := osexec.CommandContext(ctx, opBin, "signin")
	signinCmd.Stdin = os.Stdin
	signinCmd.Stdout = c.OutOrStdout()
	signinCmd.Stderr = c.ErrOrStderr()
	if err := signinCmd.Run(); err != nil {
		fmt.Fprintf(c.ErrOrStderr(), "Error: op signin failed: %v\n", err)
		return fmt.Errorf("exit %d", exitcode.BackendUnavailable)
	}
	return nil
}

// newOPInitCmd returns the `op-init <service>` command.
// Secret values are read via secure prompt or --from-stdin; never positional arg.
func newOPInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "op-init <service>",
		Short: "Push service credentials into a 1Password vault",
		Long: `op-init reads a secret value from a secure prompt (or --from-stdin) and
stores it in the configured 1Password vault using the op CLI.

The value is NEVER read from a positional argument.`,
		Args: cobra.ExactArgs(1),
	}

	cmd.Flags().String("field", "api_key", "field name to set in the 1Password item")
	cmd.Flags().Bool("from-stdin", false, "read the secret value from stdin instead of interactive prompt")

	cmd.RunE = func(c *cobra.Command, args []string) error {
		ctx := c.Context()
		service := args[0]
		field, _ := c.Flags().GetString("field")
		fromStdin, _ := c.Flags().GetBool("from-stdin")

		cfg := loadCLIConfig(c)
		cfg.Backend = "op"
		dispatch.ClearCached()
		env := llmcontext.DefaultLookup

		b, err := dispatch.Select(ctx, cfg, env)
		if err != nil {
			if errors.Is(err, backend.ErrUnavailable) {
				fmt.Fprintf(c.ErrOrStderr(),
					"Error: 1Password CLI not available. Run: brew install 1password-cli\n")
				return fmt.Errorf("exit %d", exitcode.BackendUnavailable)
			}
			fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
			return err
		}

		opBackend, ok := b.(*op.OnePasswordBackend)
		if !ok {
			fmt.Fprintf(c.ErrOrStderr(), "Error: backend is not a OnePasswordBackend\n")
			return fmt.Errorf("exit %d", exitcode.UserError)
		}

		// Read value from secure prompt or --from-stdin; never positional arg.
		var value []byte
		if fromStdin {
			scanner := bufio.NewScanner(c.InOrStdin())
			if scanner.Scan() {
				value = []byte(strings.TrimRight(scanner.Text(), "\n"))
			}
		} else {
			// Interactive masked prompt.
			fmt.Fprintf(c.OutOrStdout(), "Enter secret value for %s.%s: ", service, field)
			value, err = readPasswordFromTerminal(c.OutOrStdout())
			fmt.Fprintln(c.OutOrStdout()) // newline after masked input
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: failed to read secret: %v\n", err)
				return fmt.Errorf("exit %d", exitcode.UserError)
			}
		}

		canonical := "default/" + service + "/" + field
		if err := opBackend.Set(ctx, canonical, value, backend.Meta{}); err != nil {
			if errors.Is(err, backend.ErrLocked) {
				fmt.Fprintf(c.ErrOrStderr(), "Error: 1Password vault locked. Run: eval $(op signin)\n")
				return fmt.Errorf("exit %d", exitcode.BackendUnavailable)
			}
			fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
			return err
		}

		// No value in output.
		vaultName := "Keylatch"
		if cfg.OP != nil && cfg.OP.Vault != "" {
			vaultName = cfg.OP.Vault
		}
		fmt.Fprintf(c.OutOrStdout(), "Pushed %s to 1Password vault %s\n", service, vaultName)
		return nil
	}

	return cmd
}

// newOPListCmd returns the `op-list` command.
func newOPListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "op-list",
		Short: "List Keylatch-managed items in the 1Password vault",
		Long:  `op-list lists all items managed by Keylatch in the configured 1Password vault. No field values or accessor UUIDs are printed.`,
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()

			cfg := loadCLIConfig(c)
			cfg.Backend = "op"
			dispatch.ClearCached()
			env := llmcontext.DefaultLookup

			b, err := dispatch.Select(ctx, cfg, env)
			if err != nil {
				if errors.Is(err, backend.ErrUnavailable) {
					fmt.Fprintf(c.ErrOrStderr(),
						"Error: 1Password CLI not available. Run: brew install 1password-cli\n")
					return fmt.Errorf("exit %d", exitcode.BackendUnavailable)
				}
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				return err
			}

			entries, err := b.List(ctx, "")
			if err != nil {
				if errors.Is(err, backend.ErrUnavailable) {
					fmt.Fprintf(c.ErrOrStderr(), "Run: brew install 1password-cli\n")
					return fmt.Errorf("exit %d", exitcode.BackendUnavailable)
				}
				if errors.Is(err, backend.ErrLocked) {
					fmt.Fprintf(c.ErrOrStderr(), "Error: Run: eval $(op signin)\n")
					return fmt.Errorf("exit %d", exitcode.BackendUnavailable)
				}
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				return err
			}

			vaultName := "Keylatch"
			if cfg.OP != nil && cfg.OP.Vault != "" {
				vaultName = cfg.OP.Vault
			}

			if len(entries) == 0 {
				fmt.Fprintf(c.OutOrStdout(),
					"No Keylatch-managed items found in vault %s\n", vaultName)
				return nil
			}

			// Table header: connection | last_updated (no values, no UUIDs).
			fmt.Fprintf(c.OutOrStdout(), "%-30s  %-30s\n", "CONNECTION/FIELD", "LAST_UPDATED")
			fmt.Fprintf(c.OutOrStdout(), "%s  %s\n",
				strings.Repeat("-", 30), strings.Repeat("-", 30))
			for _, e := range entries {
				updated := ""
				if !e.UpdatedAt.IsZero() {
					updated = e.UpdatedAt.Format("2006-01-02T15:04:05Z")
				}
				fmt.Fprintf(c.OutOrStdout(), "%-30s  %-30s\n", e.Path, updated)
			}
			return nil
		},
	}
}

// readPasswordFromTerminal reads a masked password from the terminal.
// Falls back to bufio if the terminal is not available (e.g. in tests).
func readPasswordFromTerminal(w io.Writer) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		return term.ReadPassword(fd)
	}
	// Non-interactive fallback (tests, pipes).
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return []byte(strings.TrimRight(scanner.Text(), "\n")), nil
	}
	return nil, scanner.Err()
}

// ensure op package is used.
var _ *op.OnePasswordBackend
