package envelope_test

// envelope_extra_test.go adds coverage for uncovered paths in the envelope package:
//   - NonceLen (0% — never called)
//   - Seal (0% — the top-level dispatcher)
//   - SealXChaCha20 wrong-key-size path
//   - SealAESGCM wrong-key-size and wrong-nonce-size paths
//   - openXChaCha20 wrong-key-size path (via Open with bad DEK length)
//   - openAESGCM wrong-key-size path (via Open with bad DEK length)
//   - SealXChaChaWithNonce bad key-size path

import (
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/envelope"
)

// ---------------------------------------------------------------------------
// NonceLen
// ---------------------------------------------------------------------------

func TestNonceLen(t *testing.T) {
	t.Parallel()
	cases := []struct {
		alg  envelope.Algorithm
		want int
	}{
		{envelope.XChaCha20Poly1305, 24},
		{envelope.AES256GCM, 12},
		{"unknown", -1},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.alg), func(t *testing.T) {
			t.Parallel()
			got := envelope.NonceLen(tc.alg)
			if got != tc.want {
				t.Errorf("NonceLen(%q) = %d, want %d", tc.alg, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Seal — dispatcher
// ---------------------------------------------------------------------------

func TestSeal_XChaCha20_RoundTrip(t *testing.T) {
	t.Parallel()
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 1)
	}
	plaintext := []byte("Seal dispatcher test")
	aad := []byte("aad-data")

	ct, nonce, err := envelope.Seal(envelope.XChaCha20Poly1305, dek, plaintext, aad, nil, 0)
	if err != nil {
		t.Fatalf("Seal(XChaCha20): %v", err)
	}
	if len(nonce) != 24 {
		t.Errorf("nonce len = %d, want 24", len(nonce))
	}
	got, err := envelope.Open(envelope.XChaCha20Poly1305, dek, ct, nonce, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("plaintext mismatch")
	}
}

func TestSeal_AESGCM_RoundTrip(t *testing.T) {
	t.Parallel()
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 2)
	}
	plaintext := []byte("Seal AES-GCM test")
	aad := []byte("gcm-aad")
	nonce := make([]byte, 12)
	np := &staticNonce{nonce: nonce}

	ct, nonceOut, err := envelope.Seal(envelope.AES256GCM, dek, plaintext, aad, np, 1)
	if err != nil {
		t.Fatalf("Seal(AES256GCM): %v", err)
	}
	got, err := envelope.Open(envelope.AES256GCM, dek, ct, nonceOut, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("plaintext mismatch")
	}
}

func TestSeal_UnknownAlgorithm_Error(t *testing.T) {
	t.Parallel()
	_, _, err := envelope.Seal("not-an-alg", make([]byte, 32), []byte("pt"), nil, nil, 0)
	if !errors.Is(err, envelope.ErrAlgorithmUnknown) {
		t.Errorf("expected ErrAlgorithmUnknown, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// SealXChaCha20 — wrong key size
// ---------------------------------------------------------------------------

func TestSealXChaCha20_WrongKeySize_Error(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		dekSz int
	}{
		{"empty", 0},
		{"too_short_16", 16},
		{"too_long_64", 64},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := envelope.SealXChaCha20(make([]byte, tc.dekSz), []byte("pt"), nil)
			if !errors.Is(err, envelope.ErrAlgorithmUnknown) {
				t.Errorf("SealXChaCha20 with %d-byte key: expected ErrAlgorithmUnknown, got %v", tc.dekSz, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SealAESGCM — wrong key size, wrong nonce size, np error
// ---------------------------------------------------------------------------

func TestSealAESGCM_WrongKeySize_Error(t *testing.T) {
	t.Parallel()
	np := &staticNonce{nonce: make([]byte, 12)}
	_, _, err := envelope.SealAESGCM(make([]byte, 16), []byte("pt"), nil, np, 1)
	if !errors.Is(err, envelope.ErrAlgorithmUnknown) {
		t.Errorf("expected ErrAlgorithmUnknown for 16-byte DEK, got %v", err)
	}
}

func TestSealAESGCM_WrongNonceSize_Error(t *testing.T) {
	t.Parallel()
	// A nonce provider that returns a nonce of the wrong length.
	np := &staticNonce{nonce: make([]byte, 8)} // 8 bytes, not 12
	_, _, err := envelope.SealAESGCM(make([]byte, 32), []byte("pt"), nil, np, 1)
	if err == nil {
		t.Error("expected error for 8-byte nonce, got nil")
	}
}

type errorNonce struct{ err error }

func (e *errorNonce) Next(_ envelope.Algorithm, _ int) ([]byte, error) {
	return nil, e.err
}

func TestSealAESGCM_NonceProviderError(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("nonce fail")
	np := &errorNonce{err: wantErr}
	_, _, err := envelope.SealAESGCM(make([]byte, 32), []byte("pt"), nil, np, 1)
	if err == nil {
		t.Error("expected error from failing nonce provider, got nil")
	}
}

// ---------------------------------------------------------------------------
// openXChaCha20 via Open — wrong DEK size
// ---------------------------------------------------------------------------

func TestOpen_XChaCha20_WrongDEKSize_Error(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		dekSz int
	}{
		{"empty", 0},
		{"16", 16},
		{"64", 64},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := envelope.Open(
				envelope.XChaCha20Poly1305,
				make([]byte, tc.dekSz),
				[]byte("ct"),
				make([]byte, 24),
				nil,
			)
			if !errors.Is(err, envelope.ErrAEADAuthFailed) {
				t.Errorf("Open with %d-byte DEK: expected ErrAEADAuthFailed, got %v", tc.dekSz, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// openAESGCM via Open — wrong DEK size
// ---------------------------------------------------------------------------

func TestOpen_AESGCM_WrongDEKSize_Error(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		dekSz int
	}{
		{"empty", 0},
		{"16", 16},
		{"64", 64},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := envelope.Open(
				envelope.AES256GCM,
				make([]byte, tc.dekSz),
				[]byte("ct"),
				make([]byte, 12),
				nil,
			)
			if !errors.Is(err, envelope.ErrAEADAuthFailed) {
				t.Errorf("Open AES-GCM with %d-byte DEK: expected ErrAEADAuthFailed, got %v", tc.dekSz, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SealXChaChaWithNonce — wrong key size
// ---------------------------------------------------------------------------

func TestSealXChaChaWithNonce_WrongKeySize_Error(t *testing.T) {
	t.Parallel()
	_, err := envelope.SealXChaChaWithNonce(make([]byte, 16), []byte("pt"), make([]byte, 24), nil)
	if err == nil {
		t.Error("expected error for 16-byte key in SealXChaChaWithNonce, got nil")
	}
}

func TestSealXChaChaWithNonce_RoundTrip(t *testing.T) {
	t.Parallel()
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 5)
	}
	nonce := make([]byte, 24)
	for i := range nonce {
		nonce[i] = byte(i + 99)
	}
	plaintext := []byte("with-nonce-test")
	aad := []byte("extra")

	ct, err := envelope.SealXChaChaWithNonce(dek, plaintext, nonce, aad)
	if err != nil {
		t.Fatalf("SealXChaChaWithNonce: %v", err)
	}

	got, err := envelope.Open(envelope.XChaCha20Poly1305, dek, ct, nonce, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, plaintext)
	}
}

// ---------------------------------------------------------------------------
// Open — uniform oracle covers both aesGCM and xchacha paths with wrong AAD
// ---------------------------------------------------------------------------

func TestOpen_AESGCM_TamperedAAD_Error(t *testing.T) {
	t.Parallel()
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 3)
	}
	nonce := make([]byte, 12)
	np := &staticNonce{nonce: nonce}
	plaintext := []byte("aad-test")
	aad := []byte("correct-aad")

	ct, nonceOut, err := envelope.SealAESGCM(dek, plaintext, aad, np, 1)
	if err != nil {
		t.Fatalf("SealAESGCM: %v", err)
	}

	_, err = envelope.Open(envelope.AES256GCM, dek, ct, nonceOut, []byte("wrong-aad"))
	if !errors.Is(err, envelope.ErrAEADAuthFailed) {
		t.Errorf("tampered AAD: expected ErrAEADAuthFailed, got %v", err)
	}
}
