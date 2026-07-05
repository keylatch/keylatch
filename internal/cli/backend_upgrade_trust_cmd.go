package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/crypto/keyring"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

func init() {
	// Register upgrade-trust under the backend command group via the newBackendCmd
	// function which is called from root.go. This is accomplished by the
	// newBackendUpgradeTrustCmd() function being added in newBackendCmd.
}

// newBackendUpgradeTrustCmd returns `keylatch backend upgrade-trust`.
// Idempotent: upgrades a schema v1 keyring to the current root-of-trust schema (v2).
// Blocked in LLM sessions.
func newBackendUpgradeTrustCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upgrade-trust",
		Short: "Upgrade keyring to the current root-of-trust schema",
		Long: `Idempotent upgrade of a schema v1 keyring to the current root-of-trust schema.

Reads the existing keyring.json, synthesises a RootOfTrustRecord from the
legacy kek_type/kek_id fields, and writes back an updated schema_version=2
keyring.

If the keyring is already schema v2, this command exits with success and
prints a no-op message.

This command MUST be run as the keyring owner. It is blocked in LLM sessions.`,
		RunE: func(c *cobra.Command, _ []string) error {
			if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
				fmt.Fprintln(c.ErrOrStderr(), "[keylatch] Blocked: backend upgrade-trust is not permitted in LLM sessions")
				os.Exit(exitcode.SecurityBlock)
			}

			dryRun, _ := c.Flags().GetBool("dry-run")
			jsonOut, _ := c.Flags().GetBool("json")

			// Resolve keyring path.
			krPath, _ := c.Flags().GetString("keyring")
			if krPath == "" {
				vaultDir := paths.Vault(os.Getenv)
				krPath = filepath.Join(vaultDir, "keyring", "keyring.json")
			}

			// Read the keyring file (raw JSON, no KEK required for schema check).
			data, err := os.ReadFile(krPath)
			if err != nil {
				return fmt.Errorf("backend upgrade-trust: read keyring: %w", err)
			}

			// Parse into a generic map to read schema_version without importing
			// unexported keyring internals.
			var raw map[string]any
			if err := json.Unmarshal(data, &raw); err != nil {
				return fmt.Errorf("backend upgrade-trust: parse keyring: %w", err)
			}

			schemaVer, _ := raw["schema_version"].(float64)

			type result struct {
				KeyringPath  string `json:"keyring_path"`
				SchemaBefore int    `json:"schema_before"`
				SchemaAfter  int    `json:"schema_after"`
				Action       string `json:"action"`
				DryRun       bool   `json:"dry_run"`
			}

			res := result{
				KeyringPath:  krPath,
				SchemaBefore: int(schemaVer),
				DryRun:       dryRun,
			}

			// Check if already v2.
			if int(schemaVer) >= 2 {
				res.SchemaAfter = int(schemaVer)
				res.Action = "no-op"
				return printUpgradeResult(c, jsonOut, res, "keyring already at schema v2 — nothing to do")
			}

			// Verify legacy fields are present.
			kekType, _ := raw["kek_type"].(string)
			if kekType == "" {
				return fmt.Errorf("backend upgrade-trust: keyring is schema v1 but missing kek_type — cannot auto-migrate")
			}

			// Synthesise roots from legacy fields.
			kekID, _ := raw["kek_id"].(string)
			if kekID == "" {
				kekID = kekType
			}

			rootType := string(keyring.LegacyKEKTypeToRootType(kekType))

			// Build the root record and term mapping.
			spec := map[string]any{
				"id":     kekID,
				"type":   rootType,
				"status": "active",
				"label":  "migrated-" + kekType,
			}

			// Build wrapped_deks from legacy terms.
			wrappedDEKs := map[string]string{}
			if termsRaw, ok := raw["terms"].([]any); ok {
				for _, termRaw := range termsRaw {
					termMap, ok := termRaw.(map[string]any)
					if !ok {
						continue
					}
					termNum, _ := termMap["term"].(float64)
					wrappedDEK, _ := termMap["wrapped_dek"].(string)
					if wrappedDEK != "" {
						wrappedDEKs[fmt.Sprintf("%d", int(termNum))] = wrappedDEK
					}
				}
			}

			rootRecord := map[string]any{
				"spec":         spec,
				"wrapped_deks": wrappedDEKs,
			}

			// Inject new fields.
			raw["schema_version"] = 2
			if roots, ok := raw["roots"]; !ok || roots == nil {
				raw["roots"] = []any{rootRecord}
			}

			res.SchemaAfter = 2
			res.Action = "upgraded"

			if dryRun {
				res.Action = "dry-run"
				return printUpgradeResult(c, jsonOut, res, fmt.Sprintf(
					"dry-run: would upgrade %s from schema v%d to v2 (kek_type=%s)",
					krPath, int(schemaVer), kekType))
			}

			// Marshal and write back atomically.
			newData, err := json.MarshalIndent(raw, "", "  ")
			if err != nil {
				return fmt.Errorf("backend upgrade-trust: marshal: %w", err)
			}
			if err := atomicWriteCLI(krPath, newData); err != nil {
				return fmt.Errorf("backend upgrade-trust: write: %w", err)
			}
			// Enforce 0o600.
			_ = os.Chmod(krPath, 0o600)

			return printUpgradeResult(c, jsonOut, res, fmt.Sprintf(
				"upgraded %s from schema v%d to v2 (kek_type=%s → root_type=%s)",
				krPath, int(schemaVer), kekType, rootType))
		},
	}
	cmd.Flags().String("keyring", "", "path to keyring.json (default: ~/.keylatch/vault/keyring/keyring.json)")
	cmd.Flags().Bool("dry-run", false, "print what would be changed without writing")
	cmd.Flags().Bool("json", false, "output result in JSON format")
	return cmd
}

// legacyKEKTypeToRootTypeCLI is now delegated to keyring.LegacyKEKTypeToRootType (Mi-4).
// This function is retained only to avoid breaking callers during transition; it is
// no longer the canonical source. Use keyring.LegacyKEKTypeToRootType directly.
//
//nolint:unused
func legacyKEKTypeToRootTypeCLI(kekType string) string {
	return string(keyring.LegacyKEKTypeToRootType(kekType))
}

func printUpgradeResult(c *cobra.Command, jsonOut bool, res any, msg string) error {
	if jsonOut {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Fprintln(c.OutOrStdout(), string(b))
		return nil
	}
	fmt.Fprintln(c.OutOrStdout(), msg)
	return nil
}
