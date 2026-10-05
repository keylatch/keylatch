// Package cli implements the keylatch command-line interface.
// migrate_cmd.go implements `keylatch migrate cipher --to <alg>`.
// Re-encrypts all vault values under a new algorithm atomically.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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

// runMigrateCipher re-encrypts every stored version under a new DEK term and
// the target algorithm.
//
// Every stored version is decrypted before anything is written, so an
// unreadable version aborts the migration with the vault untouched. Once
// writing starts, a failure restores each rewritten ciphertext, nonce,
// binding sidecar and metadata record.
func runMigrateCipher(cmd *cobra.Command, toAlgStr string) error {
	toAlg := envelope.Algorithm(toAlgStr)
	switch toAlg {
	case envelope.XChaCha20Poly1305, envelope.AES256GCM:
	default:
		return fmt.Errorf("migrate cipher: unknown algorithm %q (want xchacha20-poly1305 or aes-256-gcm)", toAlgStr)
	}

	vaultDir := paths.Vault(os.Getenv)
	krPath := paths.ResolveKeyringPath(os.Getenv)

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

	fb, err := file.Open(file.Options{Dir: vaultDir})
	if err != nil {
		return fmt.Errorf("migrate cipher: open backend: %w", err)
	}

	ctx := context.Background()

	metas, err := fb.ListMeta(ctx, "")
	if err != nil {
		return fmt.Errorf("migrate cipher: list metadata: %w", err)
	}

	if len(metas) == 0 {
		if err := updateKeyringAlgorithm(krPath, toAlg); err != nil {
			return fmt.Errorf("migrate cipher: update keyring algorithm: %w", err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "no values to migrate; keyring algorithm updated")
		return nil
	}

	items, err := readStoredVersions(vaultDir, metas, kr)
	defer func() {
		for _, it := range items {
			zeroBytes(it.plaintext)
		}
	}()
	if err != nil {
		return fmt.Errorf("migrate cipher: %w (nothing was changed)", err)
	}

	newTerm, err := kr.RotateTerm(k)
	if err != nil {
		return fmt.Errorf("migrate cipher: rotate term: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "created new DEK term %d for target algorithm %q\n", newTerm, toAlg)

	if toAlg == envelope.AES256GCM {
		if err := ensureGCMCounter(krPath, newTerm); err != nil {
			return fmt.Errorf("migrate cipher: initialise nonce counter: %w", err)
		}
	}

	kr.Zero()
	kr, _, _, err = openKeyringFromEnv()
	if err != nil {
		return fmt.Errorf("migrate cipher: reopen keyring after rotate: %w", err)
	}
	defer kr.Zero()

	newDEK, err := kr.DEKForTerm(newTerm)
	if err != nil {
		return fmt.Errorf("migrate cipher: get new DEK: %w", err)
	}

	var backups []migrateBackup
	var metaBackups []vmeta.Meta
	fail := func(err error) error {
		return rollback(cmd, fb, ctx, backups, metaBackups, err)
	}

	for _, it := range items {
		backup, err := snapshotVersion(it)
		if err != nil {
			return fail(fmt.Errorf("migrate cipher: back up %s v%d: %w", it.path, it.version, err))
		}
		backups = append(backups, backup)

		newBinding := it.binding
		newBinding.KeyTerm = newTerm
		newBinding.Algorithm = string(toAlg)
		newAAD, err := aad.Marshal(newBinding)
		if err != nil {
			return fail(fmt.Errorf("migrate cipher: marshal new AAD for %s v%d: %w", it.path, it.version, err))
		}

		var newCT, newNonce []byte
		switch toAlg {
		case envelope.XChaCha20Poly1305:
			newCT, newNonce, err = envelope.SealXChaCha20(newDEK, it.plaintext, newAAD)
		case envelope.AES256GCM:
			newCT, newNonce, err = envelope.SealAESGCM(newDEK, it.plaintext, newAAD, kr, newTerm)
		}
		if err != nil {
			return fail(fmt.Errorf("migrate cipher: re-encrypt %s v%d: %w", it.path, it.version, err))
		}
		bindingJSON, err := json.Marshal(newBinding)
		if err != nil {
			return fail(fmt.Errorf("migrate cipher: marshal binding for %s v%d: %w", it.path, it.version, err))
		}

		if err := atomicWriteCLI(it.ctPath, newCT); err != nil {
			return fail(fmt.Errorf("migrate cipher: write new ciphertext %s v%d: %w", it.path, it.version, err))
		}
		if err := atomicWriteCLI(it.ctPath+".nonce", newNonce); err != nil {
			return fail(fmt.Errorf("migrate cipher: write new nonce %s v%d: %w", it.path, it.version, err))
		}
		if err := atomicWriteCLI(it.ctPath+versionBindingSuffix, bindingJSON); err != nil {
			return fail(fmt.Errorf("migrate cipher: write binding %s v%d: %w", it.path, it.version, err))
		}
		it.meta.Versions[it.index].AAD = newBinding
	}

	now := time.Now().UTC()
	for i := range metas {
		original, err := fb.GetMeta(ctx, metas[i].Path)
		if err != nil {
			return fail(fmt.Errorf("migrate cipher: read metadata for %s: %w", metas[i].Path, err))
		}
		metas[i].UpdatedAt = now
		if err := fb.SetMeta(ctx, metas[i].Path, metas[i]); err != nil {
			return fail(fmt.Errorf("migrate cipher: update metadata for %s: %w", metas[i].Path, err))
		}
		metaBackups = append(metaBackups, original)
	}

	if err := updateKeyringAlgorithm(krPath, toAlg); err != nil {
		return fail(fmt.Errorf("migrate cipher: update keyring algorithm: %w", err))
	}

	fmt.Fprintf(cmd.OutOrStdout(), "migration complete: %d value(s) re-encrypted under %q\n", len(items), toAlg)
	return nil
}

// versionBindingSuffix names the sidecar the file backend decrypts a stored
// version with; it must be rewritten with the ciphertext.
const versionBindingSuffix = ".versionmeta"

// storedVersion is one decrypted version awaiting re-encryption.
type storedVersion struct {
	meta      *vmeta.Meta
	index     int
	path      string
	version   int
	ctPath    string
	binding   vmeta.AADBinding
	plaintext []byte
}

// readStoredVersions decrypts every version whose ciphertext is on disk.
// Destroyed versions, and versions whose ciphertext was removed, have nothing
// to migrate.
func readStoredVersions(vaultDir string, metas []vmeta.Meta, kr *keyring.Keyring) ([]storedVersion, error) {
	var items []storedVersion
	for mi := range metas {
		m := &metas[mi]
		for vi, vm := range m.Versions {
			if vm.DestroyedAt != nil {
				continue
			}
			ctPath := valuePath(vaultDir, m.Path, vm.Version)
			ct, err := os.ReadFile(ctPath)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return items, fmt.Errorf("read %s v%d: %w", m.Path, vm.Version, err)
			}
			nonce, err := os.ReadFile(ctPath + ".nonce")
			if err != nil {
				return items, fmt.Errorf("read nonce %s v%d: %w", m.Path, vm.Version, err)
			}
			binding, err := readVersionBinding(ctPath, vm.AAD)
			if err != nil {
				return items, fmt.Errorf("read binding %s v%d: %w", m.Path, vm.Version, err)
			}
			aadBytes, err := aad.Marshal(binding)
			if err != nil {
				return items, fmt.Errorf("marshal AAD for %s v%d: %w", m.Path, vm.Version, err)
			}
			dek, err := kr.DEKForTerm(binding.KeyTerm)
			if err != nil {
				return items, fmt.Errorf("get DEK for %s v%d: %w", m.Path, vm.Version, err)
			}
			plaintext, err := envelope.Open(envelope.Algorithm(binding.Algorithm), dek, ct, nonce, aadBytes)
			if err != nil {
				return items, fmt.Errorf("decrypt %s v%d: %w", m.Path, vm.Version, err)
			}
			items = append(items, storedVersion{
				meta:      m,
				index:     vi,
				path:      m.Path,
				version:   vm.Version,
				ctPath:    ctPath,
				binding:   binding,
				plaintext: plaintext,
			})
		}
	}
	return items, nil
}

// readVersionBinding returns the binding the backend decrypts with: the
// sidecar next to the ciphertext, or the metadata copy when no sidecar exists.
func readVersionBinding(ctPath string, fallback vmeta.AADBinding) (vmeta.AADBinding, error) {
	data, err := os.ReadFile(ctPath + versionBindingSuffix)
	if errors.Is(err, fs.ErrNotExist) {
		return fallback, nil
	}
	if err != nil {
		return vmeta.AADBinding{}, err
	}
	var binding vmeta.AADBinding
	if err := json.Unmarshal(data, &binding); err != nil {
		return vmeta.AADBinding{}, err
	}
	return binding, nil
}

// migrateBackup holds the original files of one stored version. A nil binding
// means no sidecar existed.
type migrateBackup struct {
	ctPath  string
	ct      []byte
	nonce   []byte
	binding []byte
}

func snapshotVersion(it storedVersion) (migrateBackup, error) {
	b := migrateBackup{ctPath: it.ctPath}
	var err error
	if b.ct, err = os.ReadFile(it.ctPath); err != nil {
		return b, err
	}
	if b.nonce, err = os.ReadFile(it.ctPath + ".nonce"); err != nil {
		return b, err
	}
	b.binding, err = os.ReadFile(it.ctPath + versionBindingSuffix)
	if errors.Is(err, fs.ErrNotExist) {
		return b, nil
	}
	return b, err
}

// rollback restores the original version files and metadata records, then
// returns the original error.
func rollback(cmd *cobra.Command, fb *file.FileBackend, ctx context.Context, backups []migrateBackup, metas []vmeta.Meta, origErr error) error {
	fmt.Fprintf(cmd.ErrOrStderr(), "migration failed (%v); rolling back %d value(s)\n", origErr, len(backups))
	var failed int
	for _, b := range backups {
		if atomicWriteCLI(b.ctPath, b.ct) != nil || atomicWriteCLI(b.ctPath+".nonce", b.nonce) != nil {
			failed++
			continue
		}
		var err error
		if b.binding == nil {
			err = os.Remove(b.ctPath + versionBindingSuffix)
			if errors.Is(err, fs.ErrNotExist) {
				err = nil
			}
		} else {
			err = atomicWriteCLI(b.ctPath+versionBindingSuffix, b.binding)
		}
		if err != nil {
			failed++
		}
	}
	if fb != nil {
		for _, m := range metas {
			if fb.SetMeta(ctx, m.Path, m) != nil {
				failed++
			}
		}
	}
	if failed > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "rollback could not restore %d file(s); restore the vault from backup\n", failed)
	}
	return origErr
}

// ensureGCMCounter records a nonce counter for term in the keyring file so
// AES-GCM sealing under that term can lease nonces before the keyring
// algorithm switches.
func ensureGCMCounter(krPath string, term int) error {
	data, err := os.ReadFile(krPath)
	if err != nil {
		return fmt.Errorf("read keyring: %w", err)
	}
	var kf keyring.KeyringFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return fmt.Errorf("parse keyring: %w", err)
	}
	if kf.GCMState == nil {
		kf.GCMState = &keyring.GCMState{LeaseSize: 1024}
	}
	if kf.GCMState.PerTerm == nil {
		kf.GCMState.PerTerm = map[int]uint64{}
	}
	if _, ok := kf.GCMState.PerTerm[term]; ok {
		return nil
	}
	kf.GCMState.PerTerm[term] = 0
	newData, err := json.Marshal(kf)
	if err != nil {
		return fmt.Errorf("marshal keyring: %w", err)
	}
	return atomicWriteCLI(krPath, newData)
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
