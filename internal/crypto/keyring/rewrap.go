package keyring

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/keylatch/keylatch/internal/crypto/kek"
)

// Rewrap moves the keyring at path from the current key-encryption key to next
// and proves the move: next alone must open the keyring and recover exactly
// the DEKs current did, so every secret that decrypted before still decrypts.
// If the proof fails the keyring is wrapped back under current and an error is
// returned; the caller must not discard current until Rewrap returns nil.
func Rewrap(path string, current, next kek.KEK) error {
	kr, err := Open(path, current)
	if err != nil {
		return fmt.Errorf("keyring.Rewrap: open with the current key: %w", err)
	}
	defer kr.Zero()

	want := kr.copyDEKs()
	defer zeroDEKs(want)

	if err := kr.RotateKEK(next); err != nil {
		return fmt.Errorf("keyring.Rewrap: %w", err)
	}

	proof := verifyUnder(path, next, want)
	if proof == nil {
		return nil
	}
	if rollback := kr.RotateKEK(current); rollback != nil {
		return errors.Join(
			fmt.Errorf("keyring.Rewrap: the new key does not open the keyring: %w", proof),
			fmt.Errorf("wrapping it back under the previous key also failed: %w", rollback),
		)
	}
	return fmt.Errorf("keyring.Rewrap: the new key does not open the keyring, which is back under the previous key: %w", proof)
}

func (kr *Keyring) copyDEKs() map[int][]byte {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	out := make(map[int][]byte, len(kr.deks))
	for term, dek := range kr.deks {
		out[term] = append([]byte(nil), dek...)
	}
	return out
}

func zeroDEKs(deks map[int][]byte) {
	for _, dek := range deks {
		clear(dek)
	}
}

func verifyUnder(path string, k kek.KEK, want map[int][]byte) error {
	reopened, err := Open(path, k)
	if err != nil {
		return err
	}
	defer reopened.Zero()
	for term, dek := range want {
		got, err := reopened.DEKForTerm(term)
		if err != nil {
			return fmt.Errorf("term %d: %w", term, err)
		}
		if subtle.ConstantTimeCompare(got, dek) != 1 {
			return fmt.Errorf("term %d: the recovered key differs", term)
		}
	}
	return nil
}
