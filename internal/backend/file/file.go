// Package file implements the envelope-encrypted file backend.
// v1.0.0: Set uses xchacha20-poly1305 AEAD (or aes-256-gcm when KEYLATCH_FIPS=1).
// Plaintext and base64 write paths are removed (T-02-02, S-INV-1).
package file

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/crypto/aad"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
	"github.com/keylatch/keylatch/internal/runner"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
	vpath "github.com/keylatch/keylatch/internal/vault/path"
)

// Options configures a FileBackend.
type Options struct {
	// Dir is the root data directory (required). Created with 0o700 if absent.
	Dir string

	// PassphraseFn is a placeholder for Phase 5 keyring integration.
	// Phase 1 does not use it.
	PassphraseFn func() ([]byte, error)
}

// FileBackend implements backend.Backend using the local filesystem.
type FileBackend struct {
	dir      string
	mu       sync.Mutex
	manifest fileManifest
	loaded   bool
	crypto   *cryptoState     //nolint:unused // Phase 5 AEAD keyring state; nil = plaintext mode
	keyring  *keyring.Keyring // Phase 5 live keyring for SetVersioned/GetVersioned dispatch
}

// Open validates opts.Dir, creates it if absent, and returns an initialized
// FileBackend. Does not open any files (lazy manifest loading).
func Open(opts Options) (*FileBackend, error) {
	if opts.Dir == "" {
		return nil, fmt.Errorf("file backend: Dir is required")
	}

	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("file backend: mkdir %q: %w", opts.Dir, err)
	}

	return &FileBackend{dir: opts.Dir}, nil
}

// OpenWithKeyring opens a FileBackend with an attached keyring so that
// SetVersioned and GetVersioned automatically encrypt/decrypt values (S5-1).
func OpenWithKeyring(opts Options, kr *keyring.Keyring) (*FileBackend, error) {
	fb, err := Open(opts)
	if err != nil {
		return nil, err
	}
	fb.keyring = kr
	return fb, nil
}

// Name implements backend.Backend.
func (fb *FileBackend) Name() string { return "file" }

// Dir returns the root directory of this FileBackend.
func (fb *FileBackend) Dir() string { return fb.dir }

// Capabilities implements backend.Backend.
func (fb *FileBackend) Capabilities() []backend.Capability {
	return []backend.Capability{
		backend.CapList,
		backend.CapMetadata,
		backend.CapImport,
		backend.CapExport,
	}
}

// Set writes value to opts.Dir/{path}/value.enc using AEAD encryption (S-INV-1, T-02-02).
// Requires a keyring — returns ErrBootstrapRequired if no keyring is configured.
// Path-traversal inputs are rejected (S-INV-11).
func (fb *FileBackend) Set(ctx context.Context, path string, value []byte, meta backend.Meta) error {
	// Require keyring: no plaintext or base64 write path in v1.0.0 (T-02-02).
	if fb.keyring == nil {
		return backend.ErrBootstrapRequired
	}

	fb.mu.Lock()
	defer fb.mu.Unlock()

	if err := fb.ensureManifestLocked(); err != nil {
		return err
	}

	// Path-traversal guard (S-INV-11 / S-FIND-23).
	dir := filepath.Join(fb.dir, filepath.FromSlash(path))
	if !strings.HasPrefix(dir, filepath.Clean(fb.dir)+string(filepath.Separator)) {
		return fmt.Errorf("file backend: path escapes vault root")
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("file backend: mkdir %q: %w", dir, err)
	}

	// AEAD encryption (T-02-02, S-INV-1, S-INV-7).
	now := time.Now().UTC()
	namespace := "default"
	if parts, err := vpath.Parts(path); err == nil {
		namespace = parts.Namespace
	}

	_, term, err := fb.keyring.ActiveDEK()
	if err != nil {
		return fmt.Errorf("file backend: get active DEK term: %w", err)
	}
	dek, err := fb.keyring.DEKForTerm(term)
	if err != nil {
		return fmt.Errorf("file backend: get DEK: %w", err)
	}

	version := meta.Version
	if version == 0 {
		version = 1
	}

	binding := vmeta.AADBinding{
		SchemaVersion: vmeta.CurrentSchemaVersion,
		Namespace:     namespace,
		Path:          path,
		Version:       version,
		KeyTerm:       term,
		BackendID:     fb.ID(),
		CreatedAt:     now,
		Algorithm:     string(fb.keyring.Algorithm()),
	}
	aadBytes, err := aad.Marshal(binding)
	if err != nil {
		return fmt.Errorf("file backend: marshal AAD: %w", err)
	}

	var ct, nonce []byte
	switch fb.keyring.Algorithm() {
	case envelope.XChaCha20Poly1305:
		ct, nonce, err = envelope.SealXChaCha20(dek, value, aadBytes)
	case envelope.AES256GCM:
		ct, nonce, err = envelope.SealAESGCM(dek, value, aadBytes, fb.keyring, term)
	default:
		return fmt.Errorf("file backend: unsupported algorithm %q", fb.keyring.Algorithm())
	}
	if err != nil {
		return fmt.Errorf("file backend: seal: %w", err)
	}

	encPath := filepath.Join(dir, "value.enc")
	if err := atomicWrite(encPath, ct, 0o600); err != nil {
		return fmt.Errorf("file backend: write value.enc for %q: %w", path, err)
	}
	noncePath := encPath + ".nonce"
	if err := atomicWrite(noncePath, nonce, 0o600); err != nil {
		_ = os.Remove(encPath)
		return fmt.Errorf("file backend: write nonce for %q: %w", path, err)
	}
	// Write sidecar binding for decryption (JSON, not canonical AAD bytes).
	bindingPath := encPath + ".aad"
	bindingJSON, _ := json.Marshal(binding)
	if err := atomicWrite(bindingPath, bindingJSON, 0o600); err != nil {
		_ = os.Remove(encPath)
		_ = os.Remove(noncePath)
		return fmt.Errorf("file backend: write aad for %q: %w", path, err)
	}

	// Update manifest.
	meta.Path = path
	if meta.Backend == "" {
		meta.Backend = "file"
	}
	if meta.Version == 0 {
		meta.Version = 1
	}
	fb.manifest[path] = meta

	if err := fb.saveManifest(); err != nil {
		return fmt.Errorf("file backend: save manifest: %w", err)
	}

	return nil
}

// Get reads value.enc, decrypts via AEAD, and returns plaintext bytes.
// Returns ErrNotFound if path is not in the manifest.
// Requires a keyring — returns ErrBootstrapRequired if no keyring is configured.
// S1-7: checks runner.OK before returning plaintext.
func (fb *FileBackend) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	// S1-7: check LLM/runner approval before returning plaintext.
	if !runner.OK(ctx) {
		return nil, backend.Meta{}, backend.ErrLocked
	}

	// Require keyring: no plaintext read path in v1.0.0 (T-02-02).
	if fb.keyring == nil {
		return nil, backend.Meta{}, backend.ErrBootstrapRequired
	}

	fb.mu.Lock()
	defer fb.mu.Unlock()

	if err := fb.ensureManifestLocked(); err != nil {
		return nil, backend.Meta{}, err
	}

	meta, ok := fb.manifest[path]
	if !ok {
		return nil, backend.Meta{}, backend.ErrNotFound
	}

	// S1-6 analog: only read value.enc on explicit Get; List/GetMeta never read it.
	encPath := filepath.Join(fb.dir, filepath.FromSlash(path), "value.enc")
	ct, err := os.ReadFile(encPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, backend.Meta{}, backend.ErrNotFound
		}
		return nil, backend.Meta{}, fmt.Errorf("file backend: read value.enc for %q: %w", path, err)
	}

	// Read nonce and AAD sidecar.
	noncePath := encPath + ".nonce"
	nonce, err := os.ReadFile(noncePath)
	if err != nil {
		return nil, backend.Meta{}, fmt.Errorf("file backend: read nonce for %q: %w", path, err)
	}
	bindingPath := encPath + ".aad"
	bindingData, err := os.ReadFile(bindingPath)
	if err != nil {
		return nil, backend.Meta{}, fmt.Errorf("file backend: read aad for %q: %w", path, err)
	}

	// AEAD decryption.
	binding, err := aad.Unmarshal(bindingData)
	if err != nil {
		return nil, backend.Meta{}, fmt.Errorf("file backend: parse aad for %q: %w", path, err)
	}
	// Re-marshal to get canonical AAD bytes (same as used during encryption).
	aadBytes, err := aad.Marshal(binding)
	if err != nil {
		return nil, backend.Meta{}, fmt.Errorf("file backend: canonical aad for %q: %w", path, err)
	}
	dek, err := fb.keyring.DEKForTerm(binding.KeyTerm)
	if err != nil {
		return nil, backend.Meta{}, fmt.Errorf("file backend: get DEK for term %d: %w", binding.KeyTerm, err)
	}
	plaintext, err := envelope.Open(envelope.Algorithm(binding.Algorithm), dek, ct, nonce, aadBytes)
	if err != nil {
		return nil, backend.Meta{}, envelope.ErrAEADAuthFailed
	}

	return plaintext, meta, nil
}

// Delete removes the path directory and updates the manifest.
// Returns ErrNotFound if the path is not present.
func (fb *FileBackend) Delete(ctx context.Context, path string) error {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	// Path-traversal guard (S-INV-11): must run before manifest lookup.
	dir := filepath.Join(fb.dir, filepath.FromSlash(path))
	if !strings.HasPrefix(filepath.Clean(dir), filepath.Clean(fb.dir)+string(filepath.Separator)) {
		return fmt.Errorf("file backend: path escapes vault root")
	}

	if err := fb.ensureManifestLocked(); err != nil {
		return err
	}

	if _, ok := fb.manifest[path]; !ok {
		return backend.ErrNotFound
	}

	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("file backend: remove %q: %w", dir, err)
	}

	delete(fb.manifest, path)

	if err := fb.saveManifest(); err != nil {
		return fmt.Errorf("file backend: save manifest after delete: %w", err)
	}

	return nil
}

// List returns metadata-only entries with paths matching the given prefix.
// MUST NOT open any value.enc files (S1-6 analog).
func (fb *FileBackend) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	if err := fb.ensureManifestLocked(); err != nil {
		return nil, err
	}

	var entries []backend.Entry
	for path, meta := range fb.manifest {
		if prefix == "" || strings.HasPrefix(path, prefix) {
			entries = append(entries, backend.Entry{Meta: meta, Exists: true})
		}
	}
	return entries, nil
}

// GetMeta returns Phase 4 metadata for path from the metadata directory.
// Returns ErrNotFound if absent. MUST NOT read value files.
// Full implementation lives in internal/backend/file/meta.go (T5-03).
func (fb *FileBackend) GetMeta(ctx context.Context, path string) (vmeta.Meta, error) {
	return getMetaFromDisk(fb.dir, path)
}

// Close is idempotent — the file backend holds no OS resources beyond the mutex.
// See ZeroKeyring (internal/backend/file/meta.go) for why Close does not
// zero the attached keyring's DEKs.
func (fb *FileBackend) Close() error {
	return nil
}

// ensureManifestLocked loads the manifest if it hasn't been loaded yet.
// Caller MUST hold fb.mu.
func (fb *FileBackend) ensureManifestLocked() error {
	if !fb.loaded {
		if err := fb.loadManifest(); err != nil {
			return err
		}
		fb.loaded = true
	}
	return nil
}

// atomicWrite writes data to path atomically via temp-file + fsync + rename.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".write-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()

	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close() // best-effort cleanup in error path
		return fmt.Errorf("chmod temp: %w", err)
	}

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close() // best-effort cleanup in error path
		return fmt.Errorf("write temp: %w", err)
	}

	if err := tmp.Sync(); err != nil {
		_ = tmp.Close() // best-effort cleanup in error path
		return fmt.Errorf("sync temp: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp to %q: %w", path, err)
	}

	cleanup = false
	return nil
}
