package cli

import (
	"fmt"
	"github.com/keylatch/keylatch/internal/audit"
	"os"
	"time"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/vault"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// readSecretValue reads a credential value from piped stdin or a hidden prompt.
func readSecretValue(c *cobra.Command, path string) ([]byte, error) {
	var value []byte
	stdin := c.InOrStdin()
	stdinFile, isFile := stdin.(*os.File)
	var err error
	if isFile && !term.IsTerminal(int(stdinFile.Fd())) {
		value, err = readFieldFromStdin(stdin)
	} else {
		value, err = promptHidden(fmt.Sprintf("Enter value for %s", path))
	}
	if err != nil {
		return nil, withExitCode(exitcode.UserError, fmt.Errorf("[keylatch] error: %w", err))
	}
	if len(value) == 0 {
		return nil, withExitCode(exitcode.UserError, fmt.Errorf("[keylatch] error: value must not be empty"))
	}
	return value, nil
}

// brokerSet stores a value through the system broker. The metadata flags are
// not stored by the broker, so passing one is refused rather than dropped.
func brokerSet(c *cobra.Command, env llmcontext.Lookup, path string) error {
	for _, f := range []string{"expires-at", "issued-at", "owner", "scope", "max-versions"} {
		if c.Flags().Changed(f) {
			return NewUsageError("set: --%s is not stored by the system broker yet; set the value without it", f)
		}
	}
	canonical, err := vault.CanonicalPath(path)
	if err != nil {
		return NewUsageError("set: %v", err)
	}
	bc, err := brokerClient(env)
	if err != nil {
		return err
	}
	value, err := readSecretValue(c, path)
	if err != nil {
		return err
	}
	defer clear(value)
	if _, err := brokerPrivileged(bc, "set", brokerapi.Request{Op: brokerapi.OpSecretSet, Path: canonical, Value: value}); err != nil {
		return err
	}
	fmt.Fprintf(c.OutOrStdout(), "[keylatch] set: %s (system broker)\n", canonical)
	return nil
}

// newSetCmd returns the `set` subcommand for writing a credential value.
// Accepts --expires-at, --issued-at, --owner, --scope, --max-versions.
// Security invariant: values MUST NOT be passed as positional arguments.
func newSetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <path>",
		Short: "Set a credential value",
		Long: `Write a credential value at the given path.

The value is read from stdin (piped) or via an interactive prompt.
Do NOT pass secret values as command-line arguments.

Example:
  echo 'sk-or-v1-...' | keylatch set openrouter.api_key
  keylatch set openrouter.api_key --expires-at 2026-08-01T00:00:00Z`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()
			cfg := loadCLIConfig(c)
			env := llmcontext.DefaultLookup

			path := args[0]

			if brokerInstalled(env) {
				return brokerSet(c, env, path)
			}

			// Parse metadata flags.
			expiresAtStr, _ := c.Flags().GetString("expires-at")
			issuedAtStr, _ := c.Flags().GetString("issued-at")
			owner, _ := c.Flags().GetString("owner")
			scope, _ := c.Flags().GetString("scope")
			maxVersions, _ := c.Flags().GetInt("max-versions")

			var partialMeta vmeta.Meta
			partialMeta.Owner = owner
			partialMeta.Scope = scope
			if maxVersions > 0 {
				partialMeta.MaxVersions = maxVersions
			}

			if expiresAtStr != "" {
				t, err := time.Parse(time.RFC3339, expiresAtStr)
				if err != nil {
					return withExitCode(exitcode.UserError, fmt.Errorf("[keylatch] error: --expires-at must be RFC3339, e.g. 2026-08-01T00:00:00Z"))
				}
				partialMeta.ExpiresAt = &t
			}

			if issuedAtStr != "" {
				t, err := time.Parse(time.RFC3339, issuedAtStr)
				if err != nil {
					return withExitCode(exitcode.UserError, fmt.Errorf("[keylatch] error: --issued-at must be RFC3339, e.g. 2026-01-01T00:00:00Z"))
				}
				partialMeta.IssuedAt = &t
			}

			// Refuse before asking for the value: it would not be stored.
			al, auditCleanup, err := requireAuditLogger("set")
			if err != nil {
				return err
			}
			defer auditCleanup()
			ctx = audit.WithEmitter(ctx, audit.AsEmitter(al))

			value, err := readSecretValue(c, path)
			if err != nil {
				return err
			}

			newVersion, err := vault.RotateValue(ctx, path, value, partialMeta, cfg, env)
			recordSet(ctx, al, path, cfg.Backend, err)
			if err != nil {
				return withExitCode(exitcode.OperationFailed, fmt.Errorf("[keylatch] error: %w", err))
			}

			// Canonicalize path for display.
			fmt.Fprintf(c.OutOrStdout(), "[keylatch] set: %s — version %d\n", path, newVersion)
			return nil
		},
	}

	cmd.Flags().String("expires-at", "", "RFC3339 expiry timestamp (e.g. 2026-08-01T00:00:00Z)")
	cmd.Flags().String("issued-at", "", "RFC3339 issue timestamp")
	cmd.Flags().String("owner", "", "owner of the credential")
	cmd.Flags().String("scope", "", "scope (e.g. 'production')")
	cmd.Flags().Int("max-versions", 0, "maximum versions to retain (0 = backend default)")

	return cmd
}
