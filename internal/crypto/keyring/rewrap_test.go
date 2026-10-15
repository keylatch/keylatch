package keyring_test

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
)

func dekMap(t *testing.T, kr *keyring.Keyring, terms ...int) map[int][]byte {
	t.Helper()
	out := map[int][]byte{}
	for _, term := range terms {
		dek, err := kr.DEKForTerm(term)
		if err != nil {
			t.Fatalf("DEKForTerm(%d): %v", term, err)
		}
		out[term] = append([]byte(nil), dek...)
	}
	return out
}

func TestRewrapKeepsEveryDEK(t *testing.T) {
	path, oldKEK := buildTestKeyring(t, t.TempDir(), "old-passphrase", envelope.XChaCha20Poly1305)
	kr, err := keyring.Open(path, oldKEK)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kr.RotateTerm(oldKEK); err != nil {
		t.Fatal(err)
	}
	before := dekMap(t, kr, 1, 2)
	kr.Zero()

	newKEK := fastKEK(t, "new-passphrase")
	if err := keyring.Rewrap(path, oldKEK, newKEK); err != nil {
		t.Fatalf("Rewrap: %v", err)
	}

	after, err := keyring.Open(path, fastKEK(t, "new-passphrase"))
	if err != nil {
		t.Fatalf("Open under the new key: %v", err)
	}
	defer after.Zero()
	for term, want := range before {
		got, err := after.DEKForTerm(term)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("term %d changed by the rewrap (err %v)", term, err)
		}
	}
	if _, err := keyring.Open(path, oldKEK); !errors.Is(err, keyring.ErrKEKMismatch) {
		t.Errorf("the old key still opens the keyring: %v", err)
	}
}

// liar wraps correctly but unwraps to the wrong bytes, like a key store that
// returns a different key on the way back.
type liar struct{ kek.KEK }

func (l liar) Unwrap(w []byte) ([]byte, error) {
	dek, err := l.KEK.Unwrap(w)
	if err == nil && len(dek) > 0 {
		dek[0] ^= 0xff
	}
	return dek, err
}

// The old key is the only way back, so a rewrap that cannot be proven leaves
// the keyring under it.
func TestRewrapRollsBackWhenTheNewKeyCannotOpenIt(t *testing.T) {
	path, oldKEK := buildTestKeyring(t, t.TempDir(), "old-passphrase", envelope.XChaCha20Poly1305)
	kr, err := keyring.Open(path, oldKEK)
	if err != nil {
		t.Fatal(err)
	}
	before := dekMap(t, kr, 1)
	kr.Zero()

	err = keyring.Rewrap(path, oldKEK, liar{fastKEK(t, "new-passphrase")})
	if err == nil {
		t.Fatal("Rewrap succeeded although the new key does not recover the DEKs")
	}

	back, openErr := keyring.Open(path, oldKEK)
	if openErr != nil {
		t.Fatalf("the keyring no longer opens under the old key: %v (rewrap error: %v)", openErr, err)
	}
	defer back.Zero()
	for term, want := range before {
		got, _ := back.DEKForTerm(term)
		if !bytes.Equal(got, want) {
			t.Errorf("term %d changed", term)
		}
	}
}

func TestRewrapNeedsTheCurrentKey(t *testing.T) {
	path, _ := buildTestKeyring(t, t.TempDir(), "old-passphrase", envelope.XChaCha20Poly1305)
	if err := keyring.Rewrap(path, fastKEK(t, "wrong"), fastKEK(t, "new")); err == nil {
		t.Fatal("Rewrap accepted a key that cannot open the keyring")
	}
	if err := keyring.Rewrap(filepath.Join(t.TempDir(), "missing.json"), fastKEK(t, "a"), fastKEK(t, "b")); err == nil {
		t.Fatal("Rewrap of a missing keyring succeeded")
	}
}
