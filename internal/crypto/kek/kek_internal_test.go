package kek

// kek_internal_test.go is in the same package (kek) to test unexported helpers.
// This covers:
//   - bwKEKWithRunner — all branches (no BW_SESSION, runner error, bad JSON, field not found, bad hex)
//   - opKEKWithRunner — runner error, bad hex key
//   - extractBWField — bad JSON, field not found, field found
//   - parseHexKey — wrong length, invalid hex chars
//   - keychainKEKWithRunner (darwin only) — short hex, invalid hex, valid round-trip
//   - trust_adapter type mapping — "keychain", "op", "bw", "age-env", unknown type
//   - trust_adapter unsupported capability methods

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/trust"
)

// internalTestParams and internalTestSalt are local copies for the internal test file.
// (testParams/testSalt in passphrase_test.go live in package kek_test, not kek.)
var internalTestParams = argon2.Params{
	Time:    1,
	Memory:  64 * 1024,
	Threads: 1,
	SaltLen: 32,
	KeyLen:  32,
}

var internalTestSalt = func() []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = byte(i)
	}
	return s
}()

// ---------------------------------------------------------------------------
// parseHexKey
// ---------------------------------------------------------------------------

func TestParseHexKey_WrongLength(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		hex  string
	}{
		{"empty", ""},
		{"too_short", "0102"},
		{"too_long", fmt.Sprintf("%0128x", 0)}, // 128 chars = 64 bytes
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseHexKey(tc.hex)
			if err == nil {
				t.Errorf("parseHexKey(%q): expected error, got nil", tc.hex)
			}
		})
	}
}

func TestParseHexKey_InvalidHexChars(t *testing.T) {
	t.Parallel()
	// 64 chars, but contains 'ZZ' which is invalid hex.
	hexStr := "gg" + fmt.Sprintf("%062x", 0) // 2 invalid + 62 valid = 64 total
	_, err := parseHexKey(hexStr)
	if err == nil {
		t.Error("parseHexKey with invalid chars: expected error, got nil")
	}
}

func TestParseHexKey_Valid(t *testing.T) {
	t.Parallel()
	// 64 lowercase hex chars = a valid 32-byte key.
	hexStr := fmt.Sprintf("%064x", 0)
	key, err := parseHexKey(hexStr)
	if err != nil {
		t.Fatalf("parseHexKey: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key len = %d, want 32", len(key))
	}
}

// ---------------------------------------------------------------------------
// extractBWField
// ---------------------------------------------------------------------------

func TestExtractBWField_InvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := extractBWField([]byte("not-json"), "field")
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestExtractBWField_FieldNotFound(t *testing.T) {
	t.Parallel()
	data := []byte(`{"fields":[{"name":"other","value":"val"}]}`)
	_, err := extractBWField(data, "missing")
	if err == nil {
		t.Error("expected error for missing field, got nil")
	}
}

func TestExtractBWField_FieldFound(t *testing.T) {
	t.Parallel()
	data := []byte(`{"fields":[{"name":"my-field","value":"my-value"}]}`)
	val, err := extractBWField(data, "my-field")
	if err != nil {
		t.Fatalf("extractBWField: %v", err)
	}
	if val != "my-value" {
		t.Errorf("got %q, want %q", val, "my-value")
	}
}

// ---------------------------------------------------------------------------
// bwKEKWithRunner
// ---------------------------------------------------------------------------

func validBWHexKey() string {
	// 32 bytes of 0x01 as hex.
	key := make([]byte, 32)
	for i := range key {
		key[i] = 1
	}
	return fmt.Sprintf("%x", key)
}

func validBWItemJSON(fieldName, value string) []byte {
	return []byte(fmt.Sprintf(`{"fields":[{"name":%q,"value":%q}]}`, fieldName, value))
}

func TestBWKEKWithRunner_NoBWSession(t *testing.T) {
	t.Setenv("BW_SESSION", "")
	_, err := bwKEKWithRunner("item", "field", func(...string) ([]byte, error) {
		return nil, nil
	})
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Errorf("expected ErrKEKUnavailable, got %v", err)
	}
}

func TestBWKEKWithRunner_RunnerFails(t *testing.T) {
	t.Setenv("BW_SESSION", "fake-session")
	_, err := bwKEKWithRunner("item", "field", func(...string) ([]byte, error) {
		return nil, fmt.Errorf("bw CLI not found")
	})
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Errorf("expected ErrKEKUnavailable, got %v", err)
	}
}

func TestBWKEKWithRunner_BadJSON(t *testing.T) {
	t.Setenv("BW_SESSION", "fake-session")
	_, err := bwKEKWithRunner("item", "field", func(...string) ([]byte, error) {
		return []byte("not-json"), nil
	})
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Errorf("expected ErrKEKUnavailable, got %v", err)
	}
}

func TestBWKEKWithRunner_FieldNotFound(t *testing.T) {
	t.Setenv("BW_SESSION", "fake-session")
	_, err := bwKEKWithRunner("item", "field", func(...string) ([]byte, error) {
		return []byte(`{"fields":[{"name":"other","value":"val"}]}`), nil
	})
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Errorf("expected ErrKEKUnavailable, got %v", err)
	}
}

func TestBWKEKWithRunner_BadHexKey(t *testing.T) {
	t.Setenv("BW_SESSION", "fake-session")
	badHex := "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" // 64 chars, invalid hex
	_, err := bwKEKWithRunner("item", "field", func(...string) ([]byte, error) {
		return validBWItemJSON("field", badHex), nil
	})
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Errorf("expected ErrKEKUnavailable, got %v", err)
	}
}

func TestBWKEKWithRunner_ValidRoundTrip(t *testing.T) {
	t.Setenv("BW_SESSION", "fake-session")
	hexKey := validBWHexKey()
	k, err := bwKEKWithRunner("myitem", "myfield", func(...string) ([]byte, error) {
		return validBWItemJSON("myfield", hexKey), nil
	})
	if err != nil {
		t.Fatalf("bwKEKWithRunner: %v", err)
	}

	// Verify ID and Type.
	if k.ID() != "bw://myitem/myfield" {
		t.Errorf("ID = %q, want %q", k.ID(), "bw://myitem/myfield")
	}
	if k.Type() != "bw" {
		t.Errorf("Type = %q, want bw", k.Type())
	}

	// Round-trip wrap/unwrap.
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 7)
	}
	wrapped, err := k.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	recovered, err := k.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if string(recovered) != string(dek) {
		t.Error("DEK mismatch after round-trip")
	}
}

func TestBWKEKWithRunner_Unwrap_TooShort(t *testing.T) {
	t.Setenv("BW_SESSION", "fake-session")
	hexKey := validBWHexKey()
	k, err := bwKEKWithRunner("item", "field", func(...string) ([]byte, error) {
		return validBWItemJSON("field", hexKey), nil
	})
	if err != nil {
		t.Fatalf("bwKEKWithRunner: %v", err)
	}
	_, err = k.Unwrap([]byte("short"))
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Errorf("expected ErrKEKUnavailable for short blob, got %v", err)
	}
}

func TestBWKEKWithRunner_Unwrap_Corrupted(t *testing.T) {
	t.Setenv("BW_SESSION", "fake-session")
	hexKey := validBWHexKey()
	k, err := bwKEKWithRunner("item", "field", func(...string) ([]byte, error) {
		return validBWItemJSON("field", hexKey), nil
	})
	if err != nil {
		t.Fatalf("bwKEKWithRunner: %v", err)
	}
	dek := make([]byte, 32)
	wrapped, err := k.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	wrapped[len(wrapped)-1] ^= 0xff
	_, err = k.Unwrap(wrapped)
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Errorf("expected ErrKEKUnavailable for corrupted blob, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// opKEKWithRunner
// ---------------------------------------------------------------------------

func TestOPKEKWithRunner_RunnerFails(t *testing.T) {
	t.Parallel()
	_, err := opKEKWithRunner("vault", "item", "field", func(...string) ([]byte, error) {
		return nil, fmt.Errorf("op CLI not found")
	})
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Errorf("expected ErrKEKUnavailable, got %v", err)
	}
}

func TestOPKEKWithRunner_BadHexKey(t *testing.T) {
	t.Parallel()
	_, err := opKEKWithRunner("vault", "item", "field", func(...string) ([]byte, error) {
		return []byte("not-hex-key-64-chars-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"), nil
	})
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Errorf("expected ErrKEKUnavailable, got %v", err)
	}
}

func validOPHexKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 9)
	}
	return []byte(fmt.Sprintf("%x\n", key))
}

func TestOPKEKWithRunner_ValidRoundTrip(t *testing.T) {
	t.Parallel()
	k, err := opKEKWithRunner("vault", "item", "field", func(...string) ([]byte, error) {
		return validOPHexKey(), nil
	})
	if err != nil {
		t.Fatalf("opKEKWithRunner: %v", err)
	}

	// Verify ID and Type.
	wantID := "op://vault/item/field"
	if k.ID() != wantID {
		t.Errorf("ID = %q, want %q", k.ID(), wantID)
	}
	if k.Type() != "op" {
		t.Errorf("Type = %q, want op", k.Type())
	}

	// Round-trip.
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 11)
	}
	wrapped, err := k.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	recovered, err := k.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if string(recovered) != string(dek) {
		t.Error("DEK mismatch after round-trip")
	}
}

func TestOPKEKWithRunner_Unwrap_TooShort(t *testing.T) {
	t.Parallel()
	k, err := opKEKWithRunner("vault", "item", "field", func(...string) ([]byte, error) {
		return validOPHexKey(), nil
	})
	if err != nil {
		t.Fatalf("opKEKWithRunner: %v", err)
	}
	_, err = k.Unwrap([]byte("short"))
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Errorf("expected ErrKEKUnavailable, got %v", err)
	}
}

func TestOPKEKWithRunner_Unwrap_Corrupted(t *testing.T) {
	t.Parallel()
	k, err := opKEKWithRunner("vault", "item", "field", func(...string) ([]byte, error) {
		return validOPHexKey(), nil
	})
	if err != nil {
		t.Fatalf("opKEKWithRunner: %v", err)
	}
	dek := make([]byte, 32)
	wrapped, err := k.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	wrapped[len(wrapped)-1] ^= 0xff
	_, err = k.Unwrap(wrapped)
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Errorf("expected ErrKEKUnavailable for corrupted blob, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// trust_adapter — Type() mapping for all branches
// ---------------------------------------------------------------------------

type mockKEK struct {
	id      string
	kekType string
}

func (m *mockKEK) Wrap(dek []byte) ([]byte, error)       { return dek, nil }
func (m *mockKEK) Unwrap(wrapped []byte) ([]byte, error) { return wrapped, nil }
func (m *mockKEK) ID() string                            { return m.id }
func (m *mockKEK) Type() string                          { return m.kekType }

func TestKEKAdapter_TypeMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		kekType  string
		wantType trust.RootType
	}{
		{"passphrase", trust.RootPassphrase},
		{"keychain", trust.RootKeychain},
		{"op", trust.RootOnePassword},
		{"bw", trust.RootBitwarden},
		{"age-env", trust.RootEncryptedFile},
		{"unknown-custom", trust.RootType("unknown-custom")},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.kekType, func(t *testing.T) {
			t.Parallel()
			k := &mockKEK{id: "test-id", kekType: tc.kekType}
			a := AsRootOfTrust(k)
			got := a.Type()
			if got != tc.wantType {
				t.Errorf("Type() = %q, want %q", got, tc.wantType)
			}
		})
	}
}

func TestKEKAdapter_ID(t *testing.T) {
	t.Parallel()
	k := &mockKEK{id: "my-id", kekType: "passphrase"}
	a := AsRootOfTrust(k)
	if a.ID() != "my-id" {
		t.Errorf("ID() = %q, want %q", a.ID(), "my-id")
	}
}

func TestKEKAdapter_Verify_Error(t *testing.T) {
	t.Parallel()
	k := &mockKEK{id: "id", kekType: "passphrase"}
	a := AsRootOfTrust(k)
	err := a.Verify(context.Background(), nil, nil, nil)
	if !errors.Is(err, trust.ErrCapabilityUnsupported) {
		t.Errorf("Verify: expected ErrCapabilityUnsupported, got %v", err)
	}
}

func TestKEKAdapter_RequirePresence_Error(t *testing.T) {
	t.Parallel()
	k := &mockKEK{id: "id", kekType: "passphrase"}
	a := AsRootOfTrust(k)
	_, err := a.RequirePresence(context.Background(), "reason")
	if !errors.Is(err, trust.ErrCapabilityUnsupported) {
		t.Errorf("RequirePresence: expected ErrCapabilityUnsupported, got %v", err)
	}
}

func TestKEKAdapter_VerifyPresenceProof_Error(t *testing.T) {
	t.Parallel()
	k := &mockKEK{id: "id", kekType: "passphrase"}
	a := AsRootOfTrust(k)
	err := a.VerifyPresenceProof(context.Background(), trust.PresenceProof{})
	if !errors.Is(err, trust.ErrCapabilityUnsupported) {
		t.Errorf("VerifyPresenceProof: expected ErrCapabilityUnsupported, got %v", err)
	}
}

func TestKEKAdapter_Attest_Error(t *testing.T) {
	t.Parallel()
	k := &mockKEK{id: "id", kekType: "passphrase"}
	a := AsRootOfTrust(k)
	_, err := a.Attest(context.Background())
	if !errors.Is(err, trust.ErrCapabilityUnsupported) {
		t.Errorf("Attest: expected ErrCapabilityUnsupported, got %v", err)
	}
}

func TestKEKAdapter_Wrap_ZeroesDEK(t *testing.T) {
	t.Parallel()
	// Wrap must zero the dek slice in-place (S11-1).
	k := &mockKEK{id: "id", kekType: "passphrase"}
	a := AsRootOfTrust(k)
	dek := []byte("this-is-a-32-byte-dek-padded!!!!")
	_, err := a.Wrap(context.Background(), dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	for i, b := range dek {
		if b != 0 {
			t.Errorf("dek[%d] = 0x%02x after Wrap, want 0 (S11-1)", i, b)
		}
	}
}

// ---------------------------------------------------------------------------
// AgeIdentityKEKFromPath — empty path
// ---------------------------------------------------------------------------

func TestAgeIdentityKEKFromPath_EmptyPath(t *testing.T) {
	t.Parallel()
	_, err := AgeIdentityKEKFromPath("", []byte("salt"))
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Errorf("expected ErrKEKUnavailable for empty path, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// keychainKEKWithRunner (darwin build tag means it's compiled on darwin)
// ---------------------------------------------------------------------------

func TestKeychainKEKWithRunner_RunnerFails(t *testing.T) {
	t.Parallel()
	_, err := keychainKEKWithRunner("test-item", func(_ string, _ ...string) ([]byte, error) {
		return nil, fmt.Errorf("security command not found")
	})
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Errorf("expected ErrKEKUnavailable, got %v", err)
	}
}

func TestKeychainKEKWithRunner_ShortHex(t *testing.T) {
	t.Parallel()
	_, err := keychainKEKWithRunner("test-item", func(_ string, _ ...string) ([]byte, error) {
		return []byte("tooshort"), nil
	})
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Errorf("expected ErrKEKUnavailable for short hex, got %v", err)
	}
}

func TestKeychainKEKWithRunner_InvalidHex(t *testing.T) {
	t.Parallel()
	// 64 chars of invalid hex.
	_, err := keychainKEKWithRunner("test-item", func(_ string, _ ...string) ([]byte, error) {
		invalid := make([]byte, 64)
		for i := range invalid {
			invalid[i] = 'z'
		}
		return invalid, nil
	})
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Errorf("expected ErrKEKUnavailable for invalid hex, got %v", err)
	}
}

func TestKeychainKEKWithRunner_ValidRoundTrip(t *testing.T) {
	t.Parallel()
	// Build a valid 64-char hex key.
	rawKey := make([]byte, 32)
	for i := range rawKey {
		rawKey[i] = byte(i + 3)
	}
	hexKey := fmt.Sprintf("%x\n", rawKey)

	k, err := keychainKEKWithRunner("test-item", func(_ string, _ ...string) ([]byte, error) {
		return []byte(hexKey), nil
	})
	if err != nil {
		t.Fatalf("keychainKEKWithRunner: %v", err)
	}

	if k.ID() != "test-item" {
		t.Errorf("ID = %q, want %q", k.ID(), "test-item")
	}
	if k.Type() != "keychain" {
		t.Errorf("Type = %q, want keychain", k.Type())
	}

	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 13)
	}
	wrapped, err := k.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	recovered, err := k.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if string(recovered) != string(dek) {
		t.Error("DEK mismatch after round-trip")
	}
}

func TestKeychainKEKWithRunner_Unwrap_TooShort(t *testing.T) {
	t.Parallel()
	rawKey := make([]byte, 32)
	hexKey := fmt.Sprintf("%x\n", rawKey)
	k, err := keychainKEKWithRunner("test-item", func(_ string, _ ...string) ([]byte, error) {
		return []byte(hexKey), nil
	})
	if err != nil {
		t.Fatalf("keychainKEKWithRunner: %v", err)
	}
	_, err = k.Unwrap([]byte("short"))
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Errorf("expected ErrKEKUnavailable, got %v", err)
	}
}

func TestKeychainKEKWithRunner_Unwrap_Corrupted(t *testing.T) {
	t.Parallel()
	rawKey := make([]byte, 32)
	for i := range rawKey {
		rawKey[i] = byte(i + 17)
	}
	hexKey := fmt.Sprintf("%x\n", rawKey)
	k, err := keychainKEKWithRunner("test-item", func(_ string, _ ...string) ([]byte, error) {
		return []byte(hexKey), nil
	})
	if err != nil {
		t.Fatalf("keychainKEKWithRunner: %v", err)
	}
	dek := make([]byte, 32)
	wrapped, err := k.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	wrapped[len(wrapped)-1] ^= 0xff
	_, err = k.Unwrap(wrapped)
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Errorf("expected ErrKEKUnavailable for corrupted blob, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// PassphraseKEK — derive error (KeyLen == 0)
// ---------------------------------------------------------------------------

func TestPassphraseKEK_DeriveError(t *testing.T) {
	t.Parallel()
	// KeyLen == 0 causes argon2.Derive to return an error.
	params := internalTestParams
	params.KeyLen = 0
	_, err := PassphraseKEK([]byte("pass"), internalTestSalt, params)
	if err == nil {
		t.Error("expected error when KeyLen=0, got nil")
	}
}

// EnvAgeIdentityKEK — file not stat-able (already tested via exported API,
// but this exercises the path via AgeIdentityKEKFromPath directly)
func TestAgeIdentityKEKFromPath_FileNotExist(t *testing.T) {
	t.Parallel()
	_, err := AgeIdentityKEKFromPath("/nonexistent/path/to/identity", []byte("salt"))
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Errorf("expected ErrKEKUnavailable, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// OS-bound coverage note: EnvAgeIdentityKEK ID() method reads the env var
// at call time. This is exercised via the exported API test in kek_coverage_test.go.
// ---------------------------------------------------------------------------

// Verify passphrase is zeroed even on error.
func TestPassphraseKEK_ZeroedOnError(t *testing.T) {
	t.Parallel()
	pp := []byte("zero-me-on-error")
	params := internalTestParams
	params.KeyLen = 0 // triggers error in Derive

	_, err := PassphraseKEK(pp, internalTestSalt, params)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	for i, b := range pp {
		if b != 0 {
			t.Errorf("passphrase[%d] = 0x%02x, want 0 (must be zeroed even on error)", i, b)
		}
	}
}

// Silence the unused import of os.
var _ = os.Getenv
