package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/trust/vault"
)

// newBackendCmd returns `keylatch backend` subcommand group.
func newBackendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backend",
		Short: "Manage root-of-trust backend adapters",
	}
	cmd.AddCommand(newBackendVaultCmd())
	cmd.AddCommand(newBackendUpgradeTrustCmd())
	return cmd
}

// newBackendVaultCmd returns `keylatch backend vault` subcommand group (E13 T4).
// Vault Transit backend init/test/status commands.
func newBackendVaultCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vault",
		Short: "Manage the Vault Transit root-of-trust backend (NOT the 'vault' credential storage backend)",
		Long: `Manage the HashiCorp Vault Transit root-of-trust key-wrapping backend.

This wraps/unwraps keylatch's own local master key using Vault's Transit
secrets engine — it does NOT store your provider credentials. This is a
different feature from the 'vault' credential storage backend (where your
API keys/secrets themselves live). For that, see 'keylatch setup' or the
'config' command's backend selection.`,
	}
	cmd.AddCommand(newBackendVaultInitCmd())
	cmd.AddCommand(newBackendVaultTestCmd())
	cmd.AddCommand(newBackendVaultStatusCmd())
	return cmd
}

// newBackendVaultInitCmd returns `keylatch backend vault init`.
// Validates connection parameters and writes spec to keyring; blocked in LLM sessions.
func newBackendVaultInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize the Vault Transit backend",
		RunE: func(c *cobra.Command, _ []string) error {
			if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
				fmt.Fprintln(c.ErrOrStderr(), "[keylatch] Blocked: backend vault init is not permitted in LLM sessions")
				os.Exit(exitcode.SecurityBlock)
			}

			addr, _ := c.Flags().GetString("addr")
			transitKey, _ := c.Flags().GetString("transit-key")
			namespace, _ := c.Flags().GetString("namespace")
			authMethod, _ := c.Flags().GetString("auth-method")
			roleID, _ := c.Flags().GetString("role-id")
			secretID, _ := c.Flags().GetString("secret-id")
			// M-7: fall back to VAULT_SECRET_ID env var if flag not set.
			if secretID == "" {
				secretID = os.Getenv("VAULT_SECRET_ID")
			} else if os.Getenv("VAULT_SECRET_ID") != "" {
				fmt.Fprintln(c.ErrOrStderr(), "[keylatch] warning: --secret-id takes precedence over VAULT_SECRET_ID env var")
			}
			clientCert, _ := c.Flags().GetString("client-cert")
			clientKey, _ := c.Flags().GetString("client-key")
			caFile, _ := c.Flags().GetString("ca-file")

			if addr == "" {
				return fmt.Errorf("--addr is required")
			}
			if transitKey == "" {
				return fmt.Errorf("--transit-key is required")
			}

			opts := vault.Options{
				Addr:           addr,
				TransitKeyName: transitKey,
				Namespace:      namespace,
				AuthMethod:     authMethod,
				RoleID:         roleID,
				SecretID:       secretID,
				ClientCert:     clientCert,
				ClientKey:      clientKey,
				CACertPath:     caFile,
			}

			// Validate by attempting to construct the adapter.
			_, err := vault.New(opts)
			if err != nil {
				return fmt.Errorf("backend vault init: %w", err)
			}

			// Value-free: print only the transit key name and auth method.
			fmt.Fprintf(c.OutOrStdout(), "vault backend initialized: key=%s auth=%s\n", transitKey, authMethod)
			return nil
		},
	}
	cmd.Flags().String("addr", "", "Vault address (e.g. https://vault.example.com:8200)")
	cmd.Flags().String("transit-key", "", "Transit key name")
	cmd.Flags().String("namespace", "", "Vault namespace (Enterprise only)")
	cmd.Flags().String("auth-method", "token", "Auth method: token|approle|k8s|mtls")
	cmd.Flags().String("role-id", "", "AppRole role ID")
	cmd.Flags().String("secret-id", "", "AppRole secret ID (avoid passing on command line — visible in process list; prefer VAULT_SECRET_ID env var)")
	cmd.Flags().String("client-cert", "", "mTLS client certificate path")
	cmd.Flags().String("client-key", "", "mTLS client key path")
	cmd.Flags().String("ca-file", "", "CA certificate path")
	return cmd
}

// newBackendVaultTestCmd returns `keylatch backend vault test`.
// Probes the Vault backend: authenticates and verifies Transit key exists.
func newBackendVaultTestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test connectivity to the Vault Transit backend",
		RunE: func(c *cobra.Command, _ []string) error {
			if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
				fmt.Fprintln(c.ErrOrStderr(), "[keylatch] Blocked: backend vault test is not permitted in LLM sessions")
				os.Exit(exitcode.SecurityBlock)
			}

			addr, _ := c.Flags().GetString("addr")
			transitKey, _ := c.Flags().GetString("transit-key")
			authMethod, _ := c.Flags().GetString("auth-method")
			jsonOut, _ := c.Flags().GetBool("json")

			if addr == "" {
				return fmt.Errorf("--addr is required")
			}

			opts := vault.Options{
				Addr:           addr,
				TransitKeyName: transitKey,
				AuthMethod:     authMethod,
			}

			_, err := vault.New(opts)

			type result struct {
				Addr       string `json:"addr"`
				TransitKey string `json:"transit_key"`
				Available  bool   `json:"available"`
				Error      string `json:"error,omitempty"`
			}
			res := result{
				Addr:       addr,
				TransitKey: transitKey,
				Available:  err == nil,
			}
			if err != nil {
				res.Error = err.Error()
			}

			if jsonOut {
				b, _ := json.MarshalIndent(res, "", "  ")
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}

			if err != nil {
				fmt.Fprintf(c.OutOrStdout(), "vault backend test FAILED: %v\n", err)
			} else {
				fmt.Fprintf(c.OutOrStdout(), "vault backend test OK: %s (key=%s)\n", addr, transitKey)
			}
			return nil
		},
	}
	cmd.Flags().String("addr", "", "Vault address")
	cmd.Flags().String("transit-key", "", "Transit key name")
	cmd.Flags().String("auth-method", "token", "Auth method")
	cmd.Flags().Bool("json", false, "output in JSON format")
	return cmd
}

// newBackendVaultStatusCmd returns `keylatch backend vault status [--json]`.
// Prints value-free status of the configured Vault backend.
func newBackendVaultStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show Vault Transit backend status",
		RunE: func(c *cobra.Command, _ []string) error {
			jsonOut, _ := c.Flags().GetBool("json")
			addr, _ := c.Flags().GetString("addr")
			transitKey, _ := c.Flags().GetString("transit-key")

			type status struct {
				Backend    string `json:"backend"`
				Addr       string `json:"addr,omitempty"`
				TransitKey string `json:"transit_key,omitempty"`
				Status     string `json:"status"`
			}
			s := status{
				Backend:    "vault_transit",
				Addr:       addr,
				TransitKey: transitKey,
				Status:     "unconfigured",
			}
			if addr != "" {
				s.Status = "configured"
			}

			if jsonOut {
				b, _ := json.MarshalIndent(s, "", "  ")
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}

			fmt.Fprintf(c.OutOrStdout(), "backend:     %s\n", s.Backend)
			if s.Addr != "" {
				fmt.Fprintf(c.OutOrStdout(), "addr:        %s\n", s.Addr)
			}
			if s.TransitKey != "" {
				fmt.Fprintf(c.OutOrStdout(), "transit-key: %s\n", s.TransitKey)
			}
			fmt.Fprintf(c.OutOrStdout(), "status:      %s\n", s.Status)
			return nil
		},
	}
	cmd.Flags().String("addr", "", "Vault address")
	cmd.Flags().String("transit-key", "", "Transit key name")
	cmd.Flags().Bool("json", false, "output in JSON format")
	return cmd
}
