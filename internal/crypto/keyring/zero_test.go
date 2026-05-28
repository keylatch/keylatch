// zero_test.go — T6-02
// Verifies that Keyring.Zero() wipes all DEK backing arrays (S5-5).
package keyring

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/crypto/kek"
)

func TestDEKZeroedAfterUse(t *testing.T) {
	dir := t.TempDir()
	krPath := filepath.Join(dir, "keyring.json")

	// Set up a known non-zero DEK.
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 1)
	}

	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 5)
	}

	params := argon2.Params{Time: 1, Memory: 16 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32}
	k, err := kek.PassphraseKEK([]byte("test-passphrase-zero"), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK: %v", err)
	}
	wrapped, err := k.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	kf := KeyringFile{
		SchemaVersion: SchemaVersion,
		Algorithm:     envelope.XChaCha20Poly1305,
		ActiveTerm:    1,
		KEKType:       "passphrase",
		Salt:          salt,
		Terms: []TermRecord{
			{
				Term:       1,
				Status:     TermActive,
				WrappedDEK: wrapped,
				CreatedAt:  time.Now().UTC().Format(time.RFC3339),
				KEKType:    "passphrase",
			},
		},
	}
	data, _ := json.Marshal(kf)
	if err := os.WriteFile(krPath, data, 0o600); err != nil {
		t.Fatalf("write keyring: %v", err)
	}

	// Re-derive KEK (passphrase was zeroed by PassphraseKEK).
	k2, err := kek.PassphraseKEK([]byte("test-passphrase-zero"), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK2: %v", err)
	}

	kr, err := Open(krPath, k2)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Get a reference to the active DEK.
	// ActiveDEK returns the slice directly from the keyring's internal map —
	// it shares the same backing array. After Zero(), that array must be all-zero.
	activeDEK, _, err := kr.ActiveDEK()
	if err != nil {
		t.Fatalf("ActiveDEK: %v", err)
	}
	if len(activeDEK) == 0 {
		t.Fatal("ActiveDEK returned empty slice")
	}

	// Confirm the DEK is non-zero before zeroing.
	allZero := true
	for _, b := range activeDEK {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("DEK is all-zero before Zero() — test setup error")
	}

	// Call Zero(). Because activeDEK shares the backing array with the keyring's
	// internal DEK slice, the range-based zero in Zero() writes through the same
	// backing array — so activeDEK will also read as all-zero afterward.
	kr.Zero()

	// Verify the backing array is zeroed via the slice we still hold.
	for i, b := range activeDEK {
		if b != 0 {
			t.Errorf("DEK byte[%d] = 0x%02x after Zero() (S5-5 violated)", i, b)
		}
	}
}
