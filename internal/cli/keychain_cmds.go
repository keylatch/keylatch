package cli

import (
	"errors"
	"fmt"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/backend/keychain"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/spf13/cobra"
)

// RegisterKeychainCommands attaches keychain-related commands to root.
// Called from Register in root.go.
func RegisterKeychainCommands(root *cobra.Command) {
	root.AddCommand(newKeychainInitCmd())
	root.AddCommand(newKeychainRepairACLCmd())
	root.AddCommand(newKeychainListCmd())
	root.AddCommand(newKeychainClearCmd())
}

// newKeychainInitCmd returns the `keychain-init [service]` command.
func newKeychainInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keychain-init [service]",
		Short: "Initialize or verify the dedicated Keylatch keychain",
		Long: `keychain-init creates the dedicated locked keychain (~/.keylatch/keylatch.keychain-db)
and stores the unlock password in the login keychain under a binary-path ACL.

Safe to re-run: an existing, working unlock password is reused rather than
regenerated. Use --force only if you have confirmed you accept losing access
to secrets stored under the current password (e.g. the login-keychain unlock
item was lost or corrupted).

Use --verify-acl to re-validate the ACL after a binary path change.`,
	}
	cmd.Flags().Bool("verify-acl", false, "verify the keychain ACL instead of initializing")
	cmd.Flags().Bool("force", false, "regenerate the unlock password even if this orphans existing secrets (DATA LOSS)")

	cmd.RunE = func(c *cobra.Command, args []string) error {
		ctx := c.Context()
		verifyACL, _ := c.Flags().GetBool("verify-acl")
		force, _ := c.Flags().GetBool("force")

		cfg := loadCLIConfig(c)
		env := llmcontext.DefaultLookup

		// Force keychain backend for this command.
		cfg.Backend = "keychain"
		dispatch.ClearCached()

		b, err := dispatch.Select(ctx, cfg, env)
		if err != nil {
			if errors.Is(err, backend.ErrUnavailable) {
				fmt.Fprintf(c.ErrOrStderr(), "Error: keychain backend unavailable: %v\n", err)
				return fmt.Errorf("exit %d", exitcode.BackendUnavailable)
			}
			fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
			return err
		}

		kb, ok := b.(*keychain.KeychainBackend)
		if !ok {
			fmt.Fprintf(c.ErrOrStderr(), "Error: backend is not a KeychainBackend\n")
			return fmt.Errorf("exit %d", exitcode.UserError)
		}

		if verifyACL {
			if err := kb.VerifyACL(ctx); err != nil {
				if errors.Is(err, backend.ErrACLMismatch) {
					fmt.Fprintf(c.ErrOrStderr(),
						"ACL mismatch: keylatch binary path differs from stored ACL entry. "+
							"Run: keylatch keychain-repair-acl\n")
					return fmt.Errorf("exit %d", exitcode.BackendUnavailable)
				}
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				return err
			}
			fmt.Fprintln(c.OutOrStdout(), "ACL OK")
			return nil
		}

		service := "default"
		if len(args) > 0 {
			service = args[0]
		}

		var initErr error
		if force {
			initErr = kb.ForceReinit(ctx, service)
		} else {
			initErr = kb.Init(ctx, service)
		}
		if initErr != nil {
			fmt.Fprintf(c.ErrOrStderr(), "Error: keychain-init: %v\n", initErr)
			return initErr
		}

		fmt.Fprintf(c.OutOrStdout(), "Keychain initialized for service: %s\n", service)
		return nil
	}

	return cmd
}

// newKeychainRepairACLCmd returns the `keychain-repair-acl` command.
func newKeychainRepairACLCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keychain-repair-acl",
		Short: "Re-issue the keychain ACL for the current binary path",
		Long:  `keychain-repair-acl updates the login-keychain ACL entry to point at the current binary path (or code-signing identity on signed builds).`,
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()
			cfg := loadCLIConfig(c)
			cfg.Backend = "keychain"
			dispatch.ClearCached()
			env := llmcontext.DefaultLookup

			b, err := dispatch.Select(ctx, cfg, env)
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				return err
			}

			kb, ok := b.(*keychain.KeychainBackend)
			if !ok {
				fmt.Fprintf(c.ErrOrStderr(), "Error: backend is not a KeychainBackend\n")
				return fmt.Errorf("exit %d", exitcode.UserError)
			}

			if err := kb.RepairACL(ctx); err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				return err
			}

			if err := kb.RepairItemACLs(ctx); err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				return err
			}

			fmt.Fprintln(c.OutOrStdout(), "ACL repaired")
			return nil
		},
	}
}

// newKeychainListCmd returns the `keychain-list` command.
func newKeychainListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keychain-list",
		Short: "List keylatch-* items in the custom keychain (names only, no values)",
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()
			cfg := loadCLIConfig(c)
			cfg.Backend = "keychain"
			dispatch.ClearCached()
			env := llmcontext.DefaultLookup

			b, err := dispatch.Select(ctx, cfg, env)
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				return err
			}

			entries, err := b.List(ctx, "")
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				return err
			}

			for _, e := range entries {
				// Output: connection/field — never print values.
				fmt.Fprintln(c.OutOrStdout(), e.Path)
			}
			return nil
		},
	}
}

// newKeychainClearCmd returns the `keychain-clear <service>` command.
func newKeychainClearCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keychain-clear <service>",
		Short: "Remove all keys for one service from the keychain",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()
			service := args[0]
			cfg := loadCLIConfig(c)
			cfg.Backend = "keychain"
			dispatch.ClearCached()
			env := llmcontext.DefaultLookup

			b, err := dispatch.Select(ctx, cfg, env)
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				return err
			}

			// List all entries for this service.
			prefix := "default/" + service + "/"
			entries, err := b.List(ctx, prefix)
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				return err
			}

			n := 0
			for _, e := range entries {
				if err := b.Delete(ctx, e.Path); err != nil {
					if !errors.Is(err, backend.ErrNotFound) {
						fmt.Fprintf(c.ErrOrStderr(), "Error deleting %q: %v\n", e.Path, err)
					}
					continue
				}
				n++
			}

			fmt.Fprintf(c.OutOrStdout(), "Cleared %d items for service %s\n", n, service)
			return nil
		},
	}
}

// loadCLIConfig loads the config file. Returns the default config on error.
func loadCLIConfig(c *cobra.Command) config.Config {
	cfg, err := config.Load(paths.Config(llmcontext.DefaultLookup))
	if err != nil {
		return config.Default()
	}
	return cfg
}
