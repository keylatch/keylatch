package envelope_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/envelope"
)

type katVector struct {
	Description string `json:"description"`
	Key         string `json:"key"`
	Nonce       string `json:"nonce"`
	AAD         string `json:"aad"`
	Plaintext   string `json:"plaintext"`
	Ciphertext  string `json:"ciphertext"`
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	if s == "" {
		return []byte{}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

func loadVectors(t *testing.T, path string) []katVector {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var vecs []katVector
	if err := json.Unmarshal(data, &vecs); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return vecs
}

func TestKATXChaCha20(t *testing.T) {
	vectors := loadVectors(t, "testdata/xchacha20-vectors.json")
	for _, v := range vectors {
		v := v
		t.Run(v.Description, func(t *testing.T) {
			key := mustDecodeHex(t, v.Key)
			nonce := mustDecodeHex(t, v.Nonce)
			aad := mustDecodeHex(t, v.AAD)
			plaintext := mustDecodeHex(t, v.Plaintext)
			wantCiphertext := mustDecodeHex(t, v.Ciphertext)

			// Use Open to verify the known ciphertext → plaintext.
			got, err := envelope.Open(envelope.XChaCha20Poly1305, key, wantCiphertext, nonce, aad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if string(got) != string(plaintext) {
				t.Errorf("plaintext mismatch\ngot:  %x\nwant: %x", got, plaintext)
			}

			// Verify that Seal with a known nonce produces the expected ciphertext.
			ct, err := envelope.SealXChaChaWithNonce(key, plaintext, nonce, aad)
			if err != nil {
				t.Fatalf("SealXChaChaWithNonce: %v", err)
			}
			if string(ct) != string(wantCiphertext) {
				t.Errorf("ciphertext mismatch\ngot:  %x\nwant: %x", ct, wantCiphertext)
			}

			t.Logf("PASS %s", v.Description)
		})
	}
}

func TestKATAESGCM(t *testing.T) {
	vectors := loadVectors(t, "testdata/aesgcm-vectors.json")
	for _, v := range vectors {
		v := v
		t.Run(v.Description, func(t *testing.T) {
			key := mustDecodeHex(t, v.Key)
			nonce := mustDecodeHex(t, v.Nonce)
			aad := mustDecodeHex(t, v.AAD)
			plaintext := mustDecodeHex(t, v.Plaintext)
			wantCiphertext := mustDecodeHex(t, v.Ciphertext)

			// Use Open to verify the known ciphertext → plaintext.
			got, err := envelope.Open(envelope.AES256GCM, key, wantCiphertext, nonce, aad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if string(got) != string(plaintext) {
				t.Errorf("plaintext mismatch\ngot:  %x\nwant: %x", got, plaintext)
			}

			// Seal using a static nonce provider.
			np := &staticNonce{nonce: nonce}
			ct, nonceOut, err := envelope.SealAESGCM(key, plaintext, aad, np, 1)
			if err != nil {
				t.Fatalf("SealAESGCM: %v", err)
			}
			if string(nonceOut) != string(nonce) {
				t.Errorf("nonce mismatch: got %x, want %x", nonceOut, nonce)
			}
			if string(ct) != string(wantCiphertext) {
				t.Errorf("ciphertext mismatch\ngot:  %x\nwant: %x", ct, wantCiphertext)
			}

			t.Logf("PASS %s", v.Description)
		})
	}
}

// staticNonce implements NonceProvider for testing with a fixed nonce.
type staticNonce struct {
	nonce []byte
}

func (s *staticNonce) Next(_ envelope.Algorithm, _ int) ([]byte, error) {
	return s.nonce, nil
}

func TestSealXChaCha20RoundTrip(t *testing.T) {
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i)
	}
	plaintext := []byte("hello, world")
	aad := []byte("test-aad")

	ct, nonce, err := envelope.SealXChaCha20(dek, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := envelope.Open(envelope.XChaCha20Poly1305, dek, ct, nonce, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, plaintext)
	}

	// Tamper with ciphertext.
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[0] ^= 0xFF
	_, err = envelope.Open(envelope.XChaCha20Poly1305, dek, tampered, nonce, aad)
	if !errors.Is(err, envelope.ErrAEADAuthFailed) {
		t.Errorf("tamper: expected ErrAEADAuthFailed, got %v", err)
	}
}

func TestSealAESGCMRoundTrip(t *testing.T) {
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 1)
	}
	nonce := make([]byte, 12)
	plaintext := []byte("AES-GCM test")
	aad := []byte("gcm-aad")

	np := &staticNonce{nonce: nonce}
	ct, nonceOut, err := envelope.SealAESGCM(dek, plaintext, aad, np, 1)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := envelope.Open(envelope.AES256GCM, dek, ct, nonceOut, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("round-trip mismatch")
	}

	// Tamper ciphertext.
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[0] ^= 0x01
	_, err = envelope.Open(envelope.AES256GCM, dek, tampered, nonceOut, aad)
	if !errors.Is(err, envelope.ErrAEADAuthFailed) {
		t.Errorf("tamper ciphertext: expected ErrAEADAuthFailed, got %v", err)
	}

	// Tamper AAD.
	_, err = envelope.Open(envelope.AES256GCM, dek, ct, nonceOut, []byte("wrong-aad"))
	if !errors.Is(err, envelope.ErrAEADAuthFailed) {
		t.Errorf("tamper AAD: expected ErrAEADAuthFailed, got %v", err)
	}

	// Tamper nonce.
	wrongNonce := make([]byte, 12)
	wrongNonce[0] = 0xFF
	_, err = envelope.Open(envelope.AES256GCM, dek, ct, wrongNonce, aad)
	if !errors.Is(err, envelope.ErrAEADAuthFailed) {
		t.Errorf("tamper nonce: expected ErrAEADAuthFailed, got %v", err)
	}
}

func TestOpenUniformOracle(t *testing.T) {
	// Use a non-zero DEK so that "wrong DEK" (all zeros) is distinguishable.
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 1)
	}
	plaintext := []byte("oracle test")
	aad := []byte("aad")

	ct, nonce, err := envelope.SealXChaCha20(dek, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	cases := []struct {
		name  string
		dek   []byte
		ct    []byte
		nonce []byte
		aad   []byte
	}{
		{
			name:  "wrong AAD",
			dek:   dek,
			ct:    ct,
			nonce: nonce,
			aad:   []byte("wrong"),
		},
		{
			name:  "wrong DEK",
			dek:   make([]byte, 32), // all zeros != original (which starts with 0x01)
			ct:    ct,
			nonce: nonce,
			aad:   aad,
		},
		{
			name:  "wrong nonce",
			dek:   dek,
			ct:    ct,
			nonce: make([]byte, 24),
			aad:   aad,
		},
		{
			name: "1-bit ciphertext flip",
			dek:  dek,
			ct: func() []byte {
				b := make([]byte, len(ct))
				copy(b, ct)
				b[0] ^= 0x01
				return b
			}(),
			nonce: nonce,
			aad:   aad,
		},
		{
			name:  "truncated ciphertext",
			dek:   dek,
			ct:    ct[:len(ct)/2],
			nonce: nonce,
			aad:   aad,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := envelope.Open(envelope.XChaCha20Poly1305, tc.dek, tc.ct, tc.nonce, tc.aad)
			if !errors.Is(err, envelope.ErrAEADAuthFailed) {
				t.Errorf("expected ErrAEADAuthFailed, got %v", err)
			}
		})
	}
}

func TestOpenUnknownAlgorithm(t *testing.T) {
	_, err := envelope.Open("unknown-alg", make([]byte, 32), []byte("ct"), make([]byte, 12), nil)
	if !errors.Is(err, envelope.ErrAlgorithmUnknown) {
		t.Errorf("expected ErrAlgorithmUnknown, got %v", err)
	}
}
