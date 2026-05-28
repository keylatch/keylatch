package envelope_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/envelope"
)

// BenchmarkEnvelopeSeal benchmarks XChaCha20-Poly1305 encryption.
func BenchmarkEnvelopeSeal(b *testing.B) {
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 1)
	}
	plaintext := make([]byte, 256)
	aad := []byte("bench-aad")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := envelope.SealXChaCha20(dek, plaintext, aad)
		if err != nil {
			b.Fatalf("SealXChaCha20: %v", err)
		}
	}
}

// BenchmarkEnvelopeOpen benchmarks XChaCha20-Poly1305 decryption.
func BenchmarkEnvelopeOpen(b *testing.B) {
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 1)
	}
	plaintext := make([]byte, 256)
	aad := []byte("bench-aad")

	// Pre-encrypt once to get a stable ciphertext and nonce.
	ct, nonce, err := envelope.SealXChaCha20(dek, plaintext, aad)
	if err != nil {
		b.Fatalf("SealXChaCha20 setup: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := envelope.Open(envelope.XChaCha20Poly1305, dek, ct, nonce, aad)
		if err != nil {
			b.Fatalf("Open: %v", err)
		}
	}
}
