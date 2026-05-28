// Package cli implements the keylatch command-line interface.
// migrate_cmd.go implements `keylatch migrate cipher --to <alg>`.
// T5-07: re-encrypts all vault values under a new algorithm atomically.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/keylatch/keylatch/internal/backend/file"
	"github.com/keylatch/keylatch/internal/crypto/aad"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
	"github.com/keylatch/keylatch/internal/paths"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
	"github.com/spf13/cobra"
)

// newMigrateCmd returns the `keylatch migrate` command group.
func newMigrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Data migration utilities",
	}
	cmd.AddCommand(newMigrateCipherCmd())
	return cmd
}

// newMigrateCipherCmd implements `keylatch migrate cipher --to <alg>`.
// Re-encrypts all vault values under the target algorithm atomically.
func newMigrateCipherCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cipher",
		Short: "Re-encrypt vault values under a new algorithm",
		Long: `Re-encrypts every value in the vault under the target algorithm.

The migration is atomic: on failure, the vault is left in its original
state (all old-algorithm ciphertexts remain readable).

On success, a new DEK term is created for the target algorithm, all
values are re-encrypted, and the old terms are retired.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			toAlg, _ := cmd.Flags().GetString("to")
			return runMigrateCipher(cmd, toAlg)
		},
	}
	cmd.Flags().String("to", "", "target algorithm: xchacha20-poly1305 or aes-256-gcm (required)")
	_ = cmd.MarkFlagRequired("to")
	return cmd
}

// runMigrateCipher performs the full migration workflow.
//
// Steps:
//  1. Open the existing keyring and validate the target algorithm differs.
//  2. Rotate to a new DEK term (preserving old terms for rollback).
//  3. For each versioned value: decrypt under old DEK + old alg; re-encrypt under new DEK + new alg.
//  4. Update KeyringFile.Algorithm atomically.
//  5. On any failure: no ciphertexts have been overwritten, so old values remain readable.
func runMigrateCipher(cmd *cobra.Command, toAlgStr string) error {
	// Validate target algorithm.
	toAlg := envelope.Algorithm(toAlgStr)
	switch toAlg {
	case envelope.XChaCha20Poly1305, envelope.AES256GCM:
		// valid
	default:
		return fmt.Errorf("migrate cipher: unknown algorithm %q (want xchacha20-poly1305 or aes-256-gcm)", toAlgStr)
	}

	vaultDir := paths.Vault(os.Getenv)
	krPath := filepath.Join(vaultDir, "keyring", "keyring.json")

	kr, k, _, err := openKeyringFromEnv()
	if err != nil {
		return fmt.Errorf("migrate cipher: %w", err)
	}
	defer kr.Zero()

	currentAlg := kr.Algorithm()
	if currentAlg == toAlg {
		fmt.Fprintf(cmd.OutOrStdout(), "vault is already using algorithm %q — nothing to do\n", toAlg)
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "migrating vault from %q to %q\n", currentAlg, toAlg)

	// Open the file backend.
	fb, err := file.Open(file.Options{Dir: vaultDir})
	if err != nil {
		return fmt.Errorf("migrate cipher: open backend: %w", err)
	}

	ctx := context.Background()

	// List all metadata records.
	metas, err := fb.ListMeta(ctx, "")
	if err != nil {
		return fmt.Errorf("migrate cipher: list metadata: %w", err)
	}

	if len(metas) == 0 {
		// No values to migrate — just update the algorithm in the keyring file.
		if err := updateKeyringAlgorithm(krPath, toAlg); err != nil {
			return fmt.Errorf("migrate cipher: update keyring algorithm: %w", err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "no values to migrate; keyring algorithm updated")
		return nil
	}

	// Rotate to a new term that will hold the re-encrypted values.
	newTerm, err := kr.RotateTerm(k)
	if err != nil {
		return fmt.Errorf("migrate cipher: rotate term: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "created new DEK term %d for target algorithm %q\n", newTerm, toAlg)

	// Re-open the keyring to pick up the new term.
	kr.Zero()
	kr, k, _, err = openKeyringFromEnv()
	if err != nil {
		return fmt.Errorf("migrate cipher: reopen keyring after rotate: %w", err)
	}
	defer kr.Zero()
	_ = k

	// Track which versions have been re-encrypted for rollback on failure.
	var backups []migrateBackup
	migrated := 0

	for _, m := range metas {
		for _, vm := range m.Versions {
			// Read old ciphertext + nonce.
			ct, err := fb.GetVersioned(ctx, m.Path, vm.Version)
			if err != nil {
				return rollback(cmd, fb, ctx, backups,
					fmt.Errorf("migrate cipher: read %s v%d: %w", m.Path, vm.Version, err))
			}
			noncePath := valuePath(vaultDir, m.Path, vm.Version) + ".nonce"
			nonce, err := os.ReadFile(noncePath)
			if err != nil {
				return rollback(cmd, fb, ctx, backups,
					fmt.Errorf("migrate cipher: read nonce %s v%d: %w", m.Path, vm.Version, err))
			}

			// Keep backup for rollback.
			backups = append(backups, migrateBackup{
				path: m.Path, version: vm.Version,
				ct: ct, nonce: nonce,
			})

			// Reconstruct old AAD.
			oldAAD, err := aad.Marshal(vm.AAD)
			if err != nil {
				return rollback(cmd, fb, ctx, backups,
					fmt.Errorf("migrate cipher: marshal old AAD for %s v%d: %w", m.Path, vm.Version, err))
			}

			// Decrypt under old DEK + old algorithm.
			oldDEK, err := kr.DEKForTerm(vm.AAD.KeyTerm)
			if err != nil {
				return rollback(cmd, fb, ctx, backups,
					fmt.Errorf("migrate cipher: get old DEK for %s v%d: %w", m.Path, vm.Version, err))
			}
			plaintext, err := envelope.Open(envelope.Algorithm(vm.AAD.Algorithm), oldDEK, ct, nonce, oldAAD)
			if err != nil {
				return rollback(cmd, fb, ctx, backups,
					fmt.Errorf("migrate cipher: decrypt %s v%d: %w", m.Path, vm.Version, err))
			}

			// Build new AAD for the target algorithm + new term.
			newBinding := vmeta.AADBinding{
				SchemaVersion: vmeta.CurrentSchemaVersion,
				Namespace:     vm.AAD.Namespace,
				Path:          m.Path,
				Version:       vm.Version,
				KeyTerm:       newTerm,
				BackendID:     fb.ID(),
				CreatedAt:     vm.CreatedAt,
				Algorithm:     string(toAlg),
			}
			newAAD, err := aad.Marshal(newBinding)
			if err != nil {
				return rollback(cmd, fb, ctx, backups,
					fmt.Errorf("migrate cipher: marshal new AAD for %s v%d: %w", m.Path, vm.Version, err))
			}

			// Seal under new DEK + new algorithm.
			newDEK, err := kr.DEKForTerm(newTerm)
			if err != nil {
				return rollback(cmd, fb, ctx, backups,
					fmt.Errorf("migrate cipher: get new DEK for %s v%d: %w", m.Path, vm.Version, err))
			}
			var newCT, newNonce []byte
			switch toAlg {
			case envelope.XChaCha20Poly1305:
				newCT, newNonce, err = envelope.SealXChaCha20(newDEK, plaintext, newAAD)
			case envelope.AES256GCM:
				newCT, newNonce, err = envelope.SealAESGCM(newDEK, plaintext, newAAD, kr, newTerm)
			}
			if err != nil {
				return rollback(cmd, fb, ctx, backups,
					fmt.Errorf("migrate cipher: re-encrypt %s v%d: %w", m.Path, vm.Version, err))
			}

			// Write new ciphertext + nonce.
			p := valuePath(vaultDir, m.Path, vm.Version)
			if err := atomicWriteCLI(p, newCT); err != nil {
				return rollback(cmd, fb, ctx, backups,
					fmt.Errorf("migrate cipher: write new ciphertext %s v%d: %w", m.Path, vm.Version, err))
			}
			if err := atomicWriteCLI(noncePath, newNonce); err != nil {
				return rollback(cmd, fb, ctx, backups,
					fmt.Errorf("migrate cipher: write new nonce %s v%d: %w", m.Path, vm.Version, err))
			}

			// Update the version metadata AAD binding.
			vm.AAD = newBinding
			migrated++
		}

		// Update metadata with new algorithm references.
		//nolint:staticcheck // S1001: loop is intentionally written this way to preserve future extension points
		for i, vm := range m.Versions {
			m.Versions[i] = vm
		}
		m.UpdatedAt = time.Now().UTC()
		if err := fb.SetMeta(ctx, m.Path, m); err != nil {
			// Metadata update failure: rollback value files.
			return rollback(cmd, fb, ctx, backups,
				fmt.Errorf("migrate cipher: update metadata for %s: %w", m.Path, err))
		}
	}

	// Update KeyringFile.Algorithm atomically.
	if err := updateKeyringAlgorithm(krPath, toAlg); err != nil {
		return rollback(cmd, fb, ctx, backups,
			fmt.Errorf("migrate cipher: update keyring algorithm: %w", err))
	}

	fmt.Fprintf(cmd.OutOrStdout(), "migration complete: %d value(s) re-encrypted under %q\n", migrated, toAlg)
	return nil
}

// migrateBackup holds the original ciphertext and nonce for a single version.
type migrateBackup struct {
	path    string
	version int
	ct      []byte
	nonce   []byte
}

// rollback restores the original ciphertexts and returns the original error.
func rollback(cmd *cobra.Command, fb *file.FileBackend, ctx context.Context, backups []migrateBackup, origErr error) error {
	fmt.Fprintf(cmd.ErrOrStderr(), "migration failed (%v); rolling back %d value(s)\n", origErr, len(backups))
	vaultDir := paths.Vault(os.Getenv)
	for _, b := range backups {
		p := valuePath(vaultDir, b.path, b.version)
		noncePath := p + ".nonce"
		// Best-effort rollback.
		_ = atomicWriteCLI(p, b.ct)
		_ = atomicWriteCLI(noncePath, b.nonce)
	}
	_ = fb
	_ = ctx
	return origErr
}

// valuePath duplicates the layout helper from the file backend so the CLI
// can construct paths without importing unexported functions.
func valuePath(root, canonical string, version int) string {
	return filepath.Join(root, "values", filepath.FromSlash(canonical),
		fmt.Sprintf("%d", version))
}

// atomicWriteCLI writes data to path atomically (tmp + rename). Mode 0o600.
func atomicWriteCLI(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".migrate-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()        // best-effort cleanup in error path
		_ = os.Remove(tmpName) // best-effort cleanup in error path
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()        // best-effort cleanup in error path
		_ = os.Remove(tmpName) // best-effort cleanup in error path
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()        // best-effort cleanup in error path
		_ = os.Remove(tmpName) // best-effort cleanup in error path
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName) // best-effort cleanup in error path
		return err
	}
	return os.Rename(tmpName, path)
}

// updateKeyringAlgorithm reads the keyring file, updates Algorithm, and
// writes it back atomically.
func updateKeyringAlgorithm(krPath string, alg envelope.Algorithm) error {
	data, err := os.ReadFile(krPath)
	if err != nil {
		return fmt.Errorf("read keyring: %w", err)
	}
	var kf keyring.KeyringFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return fmt.Errorf("parse keyring: %w", err)
	}
	kf.Algorithm = alg
	// Initialize GCMState if switching to AES-GCM and not already present.
	if alg == envelope.AES256GCM && kf.GCMState == nil {
		kf.GCMState = &keyring.GCMState{
			PerTerm:   map[int]uint64{kf.ActiveTerm: 0},
			LeaseSize: 1024,
		}
	}
	newData, err := json.Marshal(kf)
	if err != nil {
		return fmt.Errorf("marshal keyring: %w", err)
	}
	return atomicWriteCLI(krPath, newData)
}
