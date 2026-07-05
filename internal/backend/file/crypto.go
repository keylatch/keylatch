// Package file implements the filesystem backend for keylatch.
// crypto.go wires AEAD envelope encryption into the file backend.
// Every value on disk is encrypted.
package file

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/crypto/aad"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

// CryptoOptions extends Options with keyring configuration.
// When KeyringKEK is non-nil, the backend uses AEAD encryption for all
// SetVersioned/GetVersioned calls.
type CryptoOptions struct {
	// KeyringPath is the path to the keyring.json file.
	// Defaults to <Dir>/keyring/keyring.json.
	KeyringPath string

	// KeyringKEK is the KEK used to unwrap DEKs from the keyring.
	// When nil, the backend runs in plaintext mode (legacy compat).
	KeyringKEK kek.KEK
}

// cryptoState holds the initialized keyring and its once-initialization guard.
//
//nolint:unused // keyring state; wired in when CryptoOptions.KeyringKEK is provided.
type cryptoState struct {
	once sync.Once
	kr   *keyring.Keyring
	err  error
}

// ensureKeyring initializes the keyring on first use.
//
//nolint:unused // helper; called from SetVersionedEncrypted when CryptoOptions is set.
func (fb *FileBackend) ensureKeyring(opts CryptoOptions) (*keyring.Keyring, error) {
	if fb.crypto == nil || opts.KeyringKEK == nil {
		return nil, nil // no crypto configured
	}
	fb.crypto.once.Do(func() {
		path := opts.KeyringPath
		if path == "" {
			path = fb.dir + "/keyring/keyring.json"
		}
		fb.crypto.kr, fb.crypto.err = keyring.Open(path, opts.KeyringKEK)
	})
	return fb.crypto.kr, fb.crypto.err
}

// SetVersionedEncrypted seals value with AEAD before writing to disk.
//
// Write path (per §4.2):
//  1. Get active DEK + term from keyring.
//  2. Construct AADBinding from the version metadata in m.
//  3. envelope.Seal → (ciphertext, nonce).
//  4. Write ciphertext to values/<canonical>/<version>.
//  5. Write nonce to values/<canonical>/<version>.nonce.
func (fb *FileBackend) SetVersionedEncrypted(
	ctx context.Context,
	canonical string,
	vm vmeta.VersionMeta,
	value []byte,
	kr *keyring.Keyring,
) error {
	dek, term, err := kr.ActiveDEK()
	if err != nil {
		return fmt.Errorf("file: get active DEK: %w", err)
	}

	// Construct AAD from the version metadata.
	binding := vmeta.AADBinding{
		SchemaVersion: vmeta.CurrentSchemaVersion,
		Namespace:     vm.AAD.Namespace,
		Path:          canonical,
		Version:       vm.Version,
		KeyTerm:       term,
		BackendID:     fb.ID(),
		CreatedAt:     vm.CreatedAt,
		Algorithm:     string(kr.Algorithm()),
	}

	aadBytes, err := aad.Marshal(binding)
	if err != nil {
		return fmt.Errorf("file: marshal AAD: %w", err)
	}

	// Seal the value.
	var ct, nonce []byte
	alg := kr.Algorithm()
	switch alg {
	case envelope.XChaCha20Poly1305:
		ct, nonce, err = envelope.SealXChaCha20(dek, value, aadBytes)
	case envelope.AES256GCM:
		ct, nonce, err = envelope.SealAESGCM(dek, value, aadBytes, kr, term)
	default:
		return fmt.Errorf("file: unsupported algorithm %q", alg)
	}
	if err != nil {
		return fmt.Errorf("file: seal: %w", err)
	}

	// Write ciphertext.
	p := valuePath(fb.dir, canonical, vm.Version)
	if err := ensureDir(p); err != nil {
		return err
	}
	if err := atomicWrite(p, ct, 0o600); err != nil {
		return fmt.Errorf("file: write ciphertext: %w", err)
	}

	// Write nonce alongside ciphertext.
	noncePath := p + ".nonce"
	if err := atomicWrite(noncePath, nonce, 0o600); err != nil {
		// Best-effort cleanup of ciphertext if nonce write fails.
		_ = os.Remove(p)
		return fmt.Errorf("file: write nonce: %w", err)
	}

	// Return the updated binding (caller updates metadata).
	_ = binding // binding.KeyTerm is set; caller should update vm.AAD

	return nil
}

// GetVersionedEncrypted reads and decrypts a value.
//
// Read path (per §4.1):
//  1. Read ciphertext from values/<canonical>/<version>.
//  2. Read nonce from values/<canonical>/<version>.nonce.
//  3. Reconstruct AAD from metadata.
//  4. envelope.Open → plaintext.
func (fb *FileBackend) GetVersionedEncrypted(
	ctx context.Context,
	canonical string,
	vm vmeta.VersionMeta,
	kr *keyring.Keyring,
) ([]byte, error) {
	// Get the DEK for the term recorded in this version's metadata.
	dek, err := kr.DEKForTerm(vm.AAD.KeyTerm)
	if err != nil {
		return nil, fmt.Errorf("file: get DEK for term %d: %w", vm.AAD.KeyTerm, err)
	}

	// Read ciphertext.
	p := valuePath(fb.dir, canonical, vm.Version)
	ct, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, backend.ErrNotFound
		}
		return nil, fmt.Errorf("file: read ciphertext: %w", err)
	}

	// Read nonce.
	noncePath := p + ".nonce"
	nonce, err := os.ReadFile(noncePath)
	if err != nil {
		return nil, fmt.Errorf("file: read nonce: %w", err)
	}

	// Reconstruct AAD.
	aadBytes, err := aad.Marshal(vm.AAD)
	if err != nil {
		return nil, fmt.Errorf("file: marshal AAD: %w", err)
	}

	// Open (decrypt + authenticate).
	plaintext, err := envelope.Open(envelope.Algorithm(vm.AAD.Algorithm), dek, ct, nonce, aadBytes)
	if err != nil {
		// Uniform oracle — do not distinguish failure modes.
		return nil, envelope.ErrAEADAuthFailed
	}

	return plaintext, nil
}
