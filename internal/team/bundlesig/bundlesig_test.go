package bundlesig

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMessageKeepsFieldBoundaries(t *testing.T) {
	if bytes.Equal(Message("d", "ab", "c"), Message("d", "a", "bc")) {
		t.Fatal("shifting bytes between fields produced the same message")
	}
	if bytes.Equal(Message("d1", "x"), Message("d2", "x")) {
		t.Fatal("different domains produced the same message")
	}
}

func TestSignVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.key")
	priv, err := CreateKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateKeyFile(path); err == nil {
		t.Fatal("CreateKeyFile overwrote an existing key")
	}
	loaded, err := LoadKeyFile(path)
	if err != nil || !loaded.Equal(priv) {
		t.Fatalf("LoadKeyFile = %v, want the created key", err)
	}

	pub, err := ParsePublicKey(EncodePublicKey(priv.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	msg := Message("d", "payload")
	sig := Sign(priv, msg)
	if err := Verify(pub, msg, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	cases := []struct {
		name string
		msg  []byte
		sig  string
		want error
	}{
		{"other message", Message("d", "other"), sig, ErrInvalidSignature},
		{"unsigned", msg, "", ErrUnsigned},
		{"legacy digest", msg, strings.Repeat("ab", 32), ErrLegacySignature},
		{"garbage", msg, "ed25519:!!", ErrInvalidSignature},
		{"unknown scheme", msg, "rsa:abc", ErrInvalidSignature},
	}
	for _, tc := range cases {
		if err := Verify(pub, tc.msg, tc.sig); !errors.Is(err, tc.want) {
			t.Errorf("%s: Verify = %v, want %v", tc.name, err, tc.want)
		}
	}
	if err := Verify(nil, msg, sig); !errors.Is(err, ErrNoTrustedKey) {
		t.Errorf("Verify without key = %v, want ErrNoTrustedKey", err)
	}
}

func TestParsePublicKeyRejectsMalformed(t *testing.T) {
	if _, err := ParsePublicKey(""); !errors.Is(err, ErrNoTrustedKey) {
		t.Errorf("empty key: %v", err)
	}
	if _, err := ParsePublicKey("c2hvcnQ="); err == nil {
		t.Error("short key accepted")
	}
}

func TestLoadKeyFileRejectsMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.key")
	if err := os.WriteFile(path, []byte("not-a-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFile(path); err == nil {
		t.Fatal("malformed key accepted")
	}
}
