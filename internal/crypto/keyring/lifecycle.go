package keyring

import (
	"crypto/rand"
	"fmt"
	"os"
	"time"

	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/crypto/kek"
)

// RotateTerm generates a new 32-byte DEK, wraps it under kk, and appends a
// new active TermRecord to the keyring file. The previous active term is
// demoted to retired.
//
// All state changes are written atomically via a single atomicWrite.
// Returns the new term number.
func (kr *Keyring) RotateTerm(kk kek.KEK) (int, error) {
	lockPath := flockPath(kr.path)
	unlock, err := acquireFlock(lockPath)
	if err != nil {
		return 0, fmt.Errorf("keyring.RotateTerm: acquire lock: %w", err)
	}
	defer unlock()

	kr.mu.Lock()
	defer kr.mu.Unlock()

	// Re-load from disk (another process may have rotated while we waited).
	kf, err := loadFile(kr.path)
	if err != nil {
		return 0, err
	}
	kr.file = kf

	// Generate a new random DEK.
	newDEK := make([]byte, 32)
	if _, err := rand.Read(newDEK); err != nil {
		return 0, fmt.Errorf("keyring.RotateTerm: generate DEK: %w", err)
	}

	// Wrap the new DEK under the provided KEK.
	wrapped, err := kk.Wrap(newDEK)
	if err != nil {
		return 0, fmt.Errorf("keyring.RotateTerm: wrap DEK: %w", err)
	}

	newTerm := kr.file.ActiveTerm + 1

	// Demote previous active term to retired.
	for i := range kr.file.Terms {
		if kr.file.Terms[i].Status == TermActive {
			kr.file.Terms[i].Status = TermRetired
		}
	}

	// Append the new active term.
	kr.file.Terms = append(kr.file.Terms, TermRecord{
		Term:       newTerm,
		Status:     TermActive,
		WrappedDEK: wrapped,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		KEKType:    kk.Type(),
	})
	kr.file.ActiveTerm = newTerm

	// Initialize GCM nonce counter for AES-GCM vaults.
	if kr.file.GCMState != nil {
		if kr.file.GCMState.PerTerm == nil {
			kr.file.GCMState.PerTerm = make(map[int]uint64)
		}
		kr.file.GCMState.PerTerm[newTerm] = 0
	}

	// Atomic write.
	if err := saveFile(kr.path, kr.file); err != nil {
		return 0, fmt.Errorf("keyring.RotateTerm: save: %w", err)
	}

	// Update in-memory DEK map.
	kr.deks[newTerm] = newDEK

	return newTerm, nil
}

// RotateKEK re-wraps every non-destroyed term's DEK under newKEK, then
// writes the keyring atomically. This replaces the KEK without changing DEKs.
func (kr *Keyring) RotateKEK(newKEK kek.KEK) error {
	lockPath := flockPath(kr.path)
	unlock, err := acquireFlock(lockPath)
	if err != nil {
		return fmt.Errorf("keyring.RotateKEK: acquire lock: %w", err)
	}
	defer unlock()

	kr.mu.Lock()
	defer kr.mu.Unlock()

	// Re-load from disk.
	kf, err := loadFile(kr.path)
	if err != nil {
		return err
	}
	kr.file = kf

	// Re-wrap each non-destroyed term.
	for i := range kr.file.Terms {
		term := &kr.file.Terms[i]
		if term.Status == TermDestroyed {
			continue
		}
		dek, ok := kr.deks[term.Term]
		if !ok {
			return fmt.Errorf("keyring.RotateKEK: DEK for term %d not in memory", term.Term)
		}
		newWrapped, err := newKEK.Wrap(dek)
		if err != nil {
			return fmt.Errorf("keyring.RotateKEK: wrap term %d: %w", term.Term, err)
		}
		term.WrappedDEK = newWrapped
		term.KEKType = newKEK.Type()
	}
	kr.file.KEKType = newKEK.Type()

	if err := saveFile(kr.path, kr.file); err != nil {
		return fmt.Errorf("keyring.RotateKEK: save: %w", err)
	}

	return nil
}

// DestroyTerm permanently deletes the DEK for term n. The WrappedDEK is
// cleared from both the file and the in-memory map.
//
// Returns an error if term n is the current active term (rotate first) or
// if the term does not exist.
func (kr *Keyring) DestroyTerm(term int) error {
	lockPath := flockPath(kr.path)
	unlock, err := acquireFlock(lockPath)
	if err != nil {
		return fmt.Errorf("keyring.DestroyTerm: acquire lock: %w", err)
	}
	defer unlock()

	kr.mu.Lock()
	defer kr.mu.Unlock()

	// Re-load from disk.
	kf, err := loadFile(kr.path)
	if err != nil {
		return err
	}
	kr.file = kf

	if kr.file.ActiveTerm == term {
		return fmt.Errorf("keyring.DestroyTerm: cannot destroy active term %d (rotate first)", term)
	}

	found := false
	for i := range kr.file.Terms {
		if kr.file.Terms[i].Term == term {
			if kr.file.Terms[i].Status == TermDestroyed {
				return fmt.Errorf("keyring.DestroyTerm: term %d already destroyed", term)
			}
			kr.file.Terms[i].Status = TermDestroyed
			kr.file.Terms[i].WrappedDEK = nil
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("%w: term %d", ErrKeyTermNotFound, term)
	}

	// Zero the in-memory DEK.
	if dek, ok := kr.deks[term]; ok {
		for i := range dek {
			dek[i] = 0
		}
		delete(kr.deks, term)
	}

	if err := saveFile(kr.path, kr.file); err != nil {
		return fmt.Errorf("keyring.DestroyTerm: save: %w", err)
	}

	return nil
}

// flockPath returns the path to the flock file for keyring mutations.
func flockPath(keyringPath string) string {
	return keyringPath + ".lock"
}

// New creates a brand-new KeyringFile at path with the given configuration.
// It generates a random salt and first DEK, wraps the DEK under kk, and writes
// the keyring atomically. For AES-GCM vaults, the GCM nonce counter is
// initialized with the given gcmLeaseSize.
func New(path string, kk kek.KEK, alg envelope.Algorithm, gcmLeaseSize uint64) error {
	// Generate the first DEK.
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return fmt.Errorf("keyring.New: generate DEK: %w", err)
	}

	wrapped, err := kk.Wrap(dek)
	if err != nil {
		return fmt.Errorf("keyring.New: wrap DEK: %w", err)
	}

	// Zero the DEK now that it's wrapped.
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()

	// Generate a 32-byte salt.
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("keyring.New: generate salt: %w", err)
	}

	kf := KeyringFile{
		SchemaVersion: SchemaVersion,
		Algorithm:     alg,
		ActiveTerm:    1,
		KEKType:       kk.Type(),
		Salt:          salt,
		Terms: []TermRecord{
			{
				Term:       1,
				Status:     TermActive,
				WrappedDEK: wrapped,
				CreatedAt:  time.Now().UTC().Format(time.RFC3339),
				KEKType:    kk.Type(),
			},
		},
	}

	if alg == envelope.AES256GCM {
		kf.GCMState = &GCMState{
			PerTerm:   map[int]uint64{1: 0},
			LeaseSize: gcmLeaseSize,
		}
	}

	return saveFile(path, kf)
}

// NewWithSalt is like New but accepts a caller-supplied salt instead of
// generating one. Use this when the salt must be derived before KEK derivation
// (e.g. passphrase KEK where the salt is needed for Argon2id before init).
func NewWithSalt(path string, kk kek.KEK, alg envelope.Algorithm, gcmLeaseSize uint64, salt []byte) error {
	if len(salt) == 0 {
		return fmt.Errorf("keyring.NewWithSalt: salt must not be empty")
	}

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return fmt.Errorf("keyring.NewWithSalt: generate DEK: %w", err)
	}

	wrapped, err := kk.Wrap(dek)
	if err != nil {
		return fmt.Errorf("keyring.NewWithSalt: wrap DEK: %w", err)
	}

	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()

	kf := KeyringFile{
		SchemaVersion: SchemaVersion,
		Algorithm:     alg,
		ActiveTerm:    1,
		KEKType:       kk.Type(),
		Salt:          salt,
		Terms: []TermRecord{
			{
				Term:       1,
				Status:     TermActive,
				WrappedDEK: wrapped,
				CreatedAt:  time.Now().UTC().Format(time.RFC3339),
				KEKType:    kk.Type(),
			},
		},
	}

	if alg == envelope.AES256GCM {
		kf.GCMState = &GCMState{
			PerTerm:   map[int]uint64{1: 0},
			LeaseSize: gcmLeaseSize,
		}
	}

	return saveFile(path, kf)
}

// acquireFlock acquires an exclusive file lock. Returns a release function.
// On platforms where flock is not available, returns a no-op release.
func acquireFlock(path string) (release func(), err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open flock file %q: %w", path, err)
	}
	if err := flockExclusive(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("acquire flock %q: %w", path, err)
	}
	return func() {
		_ = flockUnlock(f)
		_ = f.Close()
	}, nil
}
