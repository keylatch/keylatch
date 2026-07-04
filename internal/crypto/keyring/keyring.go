package keyring

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/crypto/kek"
)

// Keyring is the in-memory state for an open keyring file.
//
// All exported methods are safe for concurrent use (they hold mu).
// AES-GCM nonce allocation additionally holds gcmFlock.
type Keyring struct {
	mu       sync.Mutex
	path     string
	file     KeyringFile
	deks     map[int][]byte // term → plaintext DEK
	gcmFlock string         // path to flock file for nonce counter

	// lease is the in-process nonce lease for AES-GCM nonce allocation.
	// Disk writes happen only once per leaseSize calls rather than every call.
	lease gcmNonceLease

	// fsyncFailHook, if non-nil, replaces the atomicWrite call in NextGCMNonce.
	// Used in fault-injection tests only.
	fsyncFailHook func() error
}

// Open loads and validates the keyring file at path and returns a live Keyring.
//
// It calls k.Unwrap for each non-destroyed term to recover the DEK map.
// Returns ErrKEKMismatch if no term can be unwrapped.
// Returns ErrKeyringCorrupt if the file fails validation.
func Open(path string, k kek.KEK) (*Keyring, error) {
	kf, err := loadFile(path)
	if err != nil {
		return nil, err
	}

	// Schema version 2 uses Roots instead of legacy KEKType.
	// For legacy schema version 1 keyrings, validate the KEKType allowlist.
	if kf.SchemaVersion == 1 {
		allowed := map[string]bool{
			"passphrase": true,
			"keychain":   true,
			"op":         true,
			"bw":         true,
			"age-env":    true,
		}
		if !allowed[kf.KEKType] {
			return nil, fmt.Errorf("%w: unsupported KEK type %q", ErrKeyringCorrupt, kf.KEKType)
		}
	}

	kr := &Keyring{
		path:     path,
		file:     kf,
		deks:     make(map[int][]byte),
		gcmFlock: filepath.Join(filepath.Dir(path), "keyring-gcm-nonce.lock"),
	}

	// Unwrap DEKs for all active/retired terms.
	anyUnwrapped := false
	for _, term := range kf.Terms {
		if term.Status == TermDestroyed {
			continue
		}
		dek, err := k.Unwrap(term.WrappedDEK)
		if err != nil {
			continue // try remaining terms
		}
		kr.deks[term.Term] = dek
		anyUnwrapped = true
	}

	if !anyUnwrapped {
		return nil, ErrKEKMismatch
	}

	return kr, nil
}

// ActiveDEK returns the DEK for the currently active term.
func (kr *Keyring) ActiveDEK() (dek []byte, term int, err error) {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	term = kr.file.ActiveTerm
	dek, ok := kr.deks[term]
	if !ok {
		return nil, 0, fmt.Errorf("%w: active term %d", ErrKeyTermNotFound, term)
	}
	return dek, term, nil
}

// DEKForTerm returns the DEK for the specified term.
// Returns ErrKeyTermNotFound if the term is absent from the keyring.
// Returns ErrKeyTermDestroyed if the term has been destroyed.
func (kr *Keyring) DEKForTerm(term int) ([]byte, error) {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	// Check file for destroyed status.
	for _, tr := range kr.file.Terms {
		if tr.Term == term && tr.Status == TermDestroyed {
			return nil, ErrKeyTermDestroyed
		}
	}

	dek, ok := kr.deks[term]
	if !ok {
		return nil, fmt.Errorf("%w: term %d", ErrKeyTermNotFound, term)
	}
	return dek, nil
}

// Algorithm returns the AEAD algorithm configured in the keyring file.
func (kr *Keyring) Algorithm() envelope.Algorithm {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	return kr.file.Algorithm
}

// Zero zeroes every DEK byte slice held in memory.
// Safe to call from a defer on process exit.
func (kr *Keyring) Zero() {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	for _, dek := range kr.deks {
		for i := range dek {
			dek[i] = 0
		}
	}
}

// Next implements envelope.NonceProvider for AES-GCM encryption.
// It calls NextGCMNonce internally.
func (kr *Keyring) Next(alg envelope.Algorithm, term int) ([]byte, error) {
	if alg != envelope.AES256GCM {
		return nil, fmt.Errorf("keyring.Next: only AES-256-GCM nonces supported")
	}
	return kr.NextGCMNonce(term)
}

// encodeGCMNonce encodes a GCM nonce as: uint32(term) || uint64(counter) big-endian.
// Total: 12 bytes.
func encodeGCMNonce(term int, counter uint64) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint32(nonce[:4], uint32(term)) //nolint:gosec // G115: term is a key term counter bounded by keyring size; overflow is not reachable in practice
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}
