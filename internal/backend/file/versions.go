package file

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
	vpath "github.com/keylatch/keylatch/internal/vault/path"
)

// SetVersioned writes raw (possibly encrypted) bytes for a specific version of
// a path using atomic write semantics (temp + fsync + rename). Mode 0o600 (S4-2).
//
// When a keyring is configured on the backend (fb.keyring != nil), the value is
// encrypted via SetVersionedEncrypted (S5-1). Otherwise the raw bytes are written.
func (fb *FileBackend) SetVersioned(ctx context.Context, path string, version int, value []byte) error {
	if fb.keyring != nil {
		// Encrypted path: build a minimal VersionMeta for AAD construction.
		_, term, err := fb.keyring.ActiveDEK()
		if err != nil {
			return fmt.Errorf("file: SetVersioned get active term: %w", err)
		}

		namespace := "default"
		if parts, perr := vpath.Parts(path); perr == nil {
			namespace = parts.Namespace
		}

		vm := vmeta.VersionMeta{
			Version:   version,
			CreatedAt: time.Now().UTC(),
			AAD: vmeta.AADBinding{
				SchemaVersion: vmeta.CurrentSchemaVersion,
				Namespace:     namespace,
				Path:          path,
				Version:       version,
				KeyTerm:       term,
				BackendID:     fb.ID(),
				CreatedAt:     time.Now().UTC(),
				Algorithm:     string(fb.keyring.Algorithm()),
			},
		}
		if err := fb.SetVersionedEncrypted(ctx, path, vm, value, fb.keyring); err != nil {
			return err
		}
		// Write a sidecar storing the KeyTerm so GetVersioned can decrypt without
		// reading the vault-layer metadata.
		return fb.writeVersionMeta(path, version, vm.AAD)
	}
	// No keyring: fail closed (T-02-03, S-INV-1). Production builds require bootstrap.
	return backend.ErrBootstrapRequired
}

// GetVersioned reads the raw bytes for a specific version of a path.
// Returns backend.ErrNotFound if the version file does not exist.
//
// When a keyring is configured (fb.keyring != nil), the ciphertext is
// decrypted via GetVersionedEncrypted (S5-1). Otherwise raw bytes are returned.
func (fb *FileBackend) GetVersioned(ctx context.Context, path string, version int) ([]byte, error) {
	if fb.keyring != nil {
		aadBinding, err := fb.readVersionMeta(path, version)
		if err != nil {
			return nil, fmt.Errorf("file: GetVersioned read sidecar: %w", err)
		}
		vm := vmeta.VersionMeta{
			Version: version,
			AAD:     aadBinding,
		}
		return fb.GetVersionedEncrypted(ctx, path, vm, fb.keyring)
	}
	// No keyring: fail closed (T-02-03). Reading raw plaintext is not supported in v1.0.0.
	return nil, backend.ErrBootstrapRequired
}

// writeVersionMeta writes the AADBinding for a version to a sidecar file so
// that GetVersioned can reconstruct the binding for decryption without
// requiring vault-layer metadata.
func (fb *FileBackend) writeVersionMeta(path string, version int, binding vmeta.AADBinding) error {
	p := valuePath(fb.dir, path, version) + ".versionmeta"
	data, err := json.Marshal(binding)
	if err != nil {
		return fmt.Errorf("file: marshal version meta: %w", err)
	}
	return atomicWrite(p, data, 0o600)
}

// readVersionMeta reads the sidecar AADBinding for a version.
func (fb *FileBackend) readVersionMeta(path string, version int) (vmeta.AADBinding, error) {
	p := valuePath(fb.dir, path, version) + ".versionmeta"
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return vmeta.AADBinding{}, backend.ErrNotFound
		}
		return vmeta.AADBinding{}, fmt.Errorf("file: read version meta: %w", err)
	}
	var binding vmeta.AADBinding
	if err := json.Unmarshal(data, &binding); err != nil {
		return vmeta.AADBinding{}, fmt.Errorf("file: parse version meta: %w", err)
	}
	return binding, nil
}

// DeleteVersioned removes the value file for a specific version. Idempotent —
// returns nil if the file does not exist.
func (fb *FileBackend) DeleteVersioned(_ context.Context, path string, version int) error {
	p := valuePath(fb.dir, path, version)
	err := os.Remove(p)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ID returns a stable unique identifier for this file backend instance.
// Used as the BackendID in AADBinding.
func (fb *FileBackend) ID() string { return "file:" + fb.dir }

// ActiveKeyTerm returns the currently active DEK term number from the keyring.
// Returns 0 if no keyring is configured (plaintext mode).
// Implements the optional KeyTermProvider interface used by vault.RotateValue.
func (fb *FileBackend) ActiveKeyTerm() (int, error) {
	if fb.keyring == nil {
		return 0, nil
	}
	_, term, err := fb.keyring.ActiveDEK()
	return term, err
}
