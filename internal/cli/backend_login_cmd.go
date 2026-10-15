package cli

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/backend/credref"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

// newBackendLoginCmd returns `keylatch backend login <id>`.
func newBackendLoginCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login <backend>",
		Short: "Store a remote backend's credential under the KEK instead of an environment variable",
		Long: `Reads the credential a remote backend authenticates with (` + strings.Join(config.RemoteBackendIDs, ", ") + `)
from the terminal, stores it wrapped by the KEK, and points backends.<id>.credential_ref at it.
The credential is never accepted as a flag or from a pipe, and an agent cannot run this command.

After login the backend no longer needs credentials in the environment; remove
them, and any allow_env_credentials setting.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			env := llmcontext.DefaultLookup
			if llmcontext.IsLLMSession(env) {
				return NewSecurityBlock("backend login is blocked in LLM sessions (it stores a credential); detected via: %s",
					strings.Join(llmcontext.Reasons(env), ", "))
			}
			if err := requireInteractiveTerminal("backend login", "KL-BACKEND-LOGIN"); err != nil {
				return err
			}

			id := config.BackendID(args[0])
			if !slices.Contains(config.RemoteBackendIDs, id) {
				return withExitCode(exitcode.UserError, fmt.Errorf("backend login: %q is not a backend that takes credentials (one of %s)", args[0], strings.Join(config.RemoteBackendIDs, ", ")))
			}
			ref, _ := c.Flags().GetString("ref")
			if ref == "" {
				ref = id
			}
			if !config.ValidCredentialRef(ref) {
				return withExitCode(exitcode.UserError, fmt.Errorf("backend login: --ref %q must be 1-64 letters, digits, '.', '_' or '-'", ref))
			}

			fields := map[string]string{}
			for _, f := range credref.Fields[id] {
				v, err := promptHidden(fmt.Sprintf("%s %s (leave empty to skip)", id, strings.ReplaceAll(f, "_", " ")))
				if err != nil {
					return withExitCode(exitcode.UserError, fmt.Errorf("backend login: %w", err))
				}
				if len(v) > 0 {
					fields[f] = string(v)
				}
				clear(v)
			}
			if len(fields) == 0 {
				return withExitCode(exitcode.UserError, errors.New("backend login: no credential entered"))
			}

			kr, k, _, err := openKeyringAt(paths.ResolveKeyringPath(os.Getenv), true)
			if err != nil {
				return NewBackendUnavailable("backend login: the KEK is not available: %v", err)
			}
			kr.Zero()
			if err := credref.Save(env, k, ref, fields); err != nil {
				return withExitCode(exitcode.OperationFailed, fmt.Errorf("backend login: %w", err))
			}

			cfg := loadCLIConfig(c)
			if cfg.Backends == nil {
				cfg.Backends = map[string]config.BackendCredentials{}
			}
			cfg.Backends[id] = config.BackendCredentials{CredentialRef: ref}
			if err := config.Save(paths.Config(env), cfg); err != nil {
				return withExitCode(exitcode.OperationFailed, fmt.Errorf("backend login: credential stored but the config was not updated: %w", err))
			}
			fmt.Fprintf(c.OutOrStdout(), "backend %s: credential stored as %q, wrapped by the KEK; backends.%s.credential_ref is set\n", id, ref, id)
			return nil
		},
	}
	cmd.Flags().String("ref", "", "name to store the credential under (default: the backend id)")
	return cmd
}
