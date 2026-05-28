package kek_test

import (
	"testing"
	"unsafe"

	"github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/crypto/kek"
)

// TestPassphraseZeroedAfterDeriveUnsafe uses unsafe.Pointer to inspect the
// backing array bytes after PassphraseKEK returns. This is the S5-6 verification.
func TestPassphraseZeroedAfterDeriveUnsafe(t *testing.T) {
	passphrase := []byte("ZERO-ME-0xDEADBEEF-SENTINEL")
	originalLen := len(passphrase)

	// Capture a pointer to the backing array before calling PassphraseKEK.
	ptr := unsafe.Pointer(&passphrase[0])

	salt := make([]byte, 32)
	_, err := kek.PassphraseKEK(passphrase, salt, argon2.Params{
		Time:    1,
		Memory:  16 * 1024,
		Threads: 1,
		SaltLen: 32,
		KeyLen:  32,
	})
	if err != nil {
		t.Fatalf("PassphraseKEK: %v", err)
	}

	// Inspect the original backing array via unsafe pointer.
	// This works because PassphraseKEK zeroes the slice in-place (same backing array).
	for i := 0; i < originalLen; i++ {
		b := *(*byte)(unsafe.Pointer(uintptr(ptr) + uintptr(i)))
		if b != 0 {
			t.Errorf("passphrase backing array[%d] = 0x%02x, want 0x00 (S5-6: passphrase not zeroed after derive)", i, b)
		}
	}
}
