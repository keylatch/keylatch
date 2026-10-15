package kek_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/kek"
)

func testKEK(t *testing.T, passphrase string) kek.KEK {
	t.Helper()
	k, err := kek.PassphraseKEK([]byte(passphrase), testSalt, testParams)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSecretFileRoundTripAndWrapped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "secret.enc")
	k := testKEK(t, "secret-file")

	if _, err := kek.LoadOrCreateSecret(path, k, false); !errors.Is(err, kek.ErrSecretMissing) {
		t.Fatalf("missing file without create: %v", err)
	}
	created, err := kek.LoadOrCreateSecret(path, k, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != kek.SecretSize {
		t.Fatalf("secret length %d", len(created))
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, created) {
		t.Fatal("secret stored in the clear")
	}
	again, err := kek.LoadOrCreateSecret(path, k, false)
	if err != nil || !bytes.Equal(again, created) {
		t.Fatalf("reload: %v", err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("secret file mode %v", info.Mode())
	}
}

func TestSecretFileNeedsSameKEK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.enc")
	if _, err := kek.LoadOrCreateSecret(path, testKEK(t, "one"), true); err != nil {
		t.Fatal(err)
	}
	if _, err := kek.LoadOrCreateSecret(path, testKEK(t, "two"), false); err == nil {
		t.Fatal("secret unwrapped under a different KEK")
	}
}
