// Package file implements the filesystem backend for keylatch.
// init.go implements keyring initialization for the file backend (Epic 04 T4-06).
package file

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
)

// InitKeyring initializes the keyring for a vault directory.
//
// It creates <vaultPath>/keyring/ with mode 0o700 and writes keyring.json
// with the first DEK wrapped under k. For AES-GCM vaults, the GCM nonce
// counter is initialized.
//
// This function is idempotent: if keyring.json already exists, it returns nil.
func InitKeyring(_ context.Context, vaultPath string, k kek.KEK, alg envelope.Algorithm) error {
	keyringDir := filepath.Join(vaultPath, "keyring")
	if err := os.MkdirAll(keyringDir, 0o700); err != nil {
		return fmt.Errorf("file: create keyring dir: %w", err)
	}

	krPath := filepath.Join(keyringDir, "keyring.json")

	// Idempotent: if already initialized, skip.
	if _, err := os.Stat(krPath); err == nil {
		return nil
	}

	kf := keyring.KeyringFile{
		SchemaVersion: keyring.SchemaVersion,
		Algorithm:     alg,
		ActiveTerm:    1,
		KEKType:       k.Type(),
	}

	// Generate 32-byte salt.
	kf.Salt = make([]byte, 32)
	if _, err := cryptoRandRead(kf.Salt); err != nil {
		return fmt.Errorf("file: generate keyring salt: %w", err)
	}

	// Generate first DEK.
	dek := make([]byte, 32)
	if _, err := cryptoRandRead(dek); err != nil {
		return fmt.Errorf("file: generate DEK: %w", err)
	}
	defer wipeBytes(dek)

	wrapped, err := k.Wrap(dek)
	if err != nil {
		return fmt.Errorf("file: wrap DEK: %w", err)
	}

	createdAt := currentTimeUTC()
	kf.Terms = []keyring.TermRecord{
		{
			Term:       1,
			Status:     keyring.TermActive,
			WrappedDEK: wrapped,
			CreatedAt:  createdAt,
			KEKType:    k.Type(),
		},
	}

	if alg == envelope.AES256GCM {
		kf.GCMState = &keyring.GCMState{
			PerTerm:   map[int]uint64{1: 0},
			LeaseSize: 1024,
		}
	}

	// Atomic write.
	importJSON, err := marshalJSON(kf)
	if err != nil {
		return fmt.Errorf("file: marshal keyring: %w", err)
	}
	return atomicWrite(krPath, importJSON, 0o600)
}

// wipeBytes zeroes a byte slice.
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
