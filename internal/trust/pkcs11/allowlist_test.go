package pkcs11_test

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/keylatch/keylatch/internal/trust"
	"github.com/keylatch/keylatch/internal/trust/pkcs11"
)

func makeTestHMAC(key []byte) func([]byte) []byte {
	return func(data []byte) []byte {
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		return mac.Sum(nil)
	}
}

func TestLoadAllowlist_ValidEntry(t *testing.T) {
	// Generate a random HMAC key.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	kekHMAC := makeTestHMAC(key)

	// Create a valid entry with correct HMAC.
	entry := pkcs11.ModuleEntry{
		ModulePath: "/tmp/test-pkcs11.so",
		SHA256Hex:  "deadbeef",
		Vendor:     "TestVendor",
	}
	entry.HMAC = pkcs11.MakeEntryHMAC(entry, kekHMAC)

	// Write user allowlist to a temp location.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tmpHome)
	}

	allowlistPath := filepath.Join(tmpHome, ".keylatch", "trust-allowlist.json")
	if err := os.MkdirAll(filepath.Dir(allowlistPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	data, _ := json.Marshal([]pkcs11.ModuleEntry{entry})
	if err := os.WriteFile(allowlistPath, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	entries, err := pkcs11.LoadAllowlist(kekHMAC)
	if err != nil {
		t.Fatalf("LoadAllowlist: %v", err)
	}

	// Verify the user entry was loaded.
	found := false
	for _, e := range entries {
		if e.ModulePath == entry.ModulePath {
			found = true
		}
	}
	if !found {
		t.Error("valid entry not found in loaded allowlist")
	}
}

func TestLoadAllowlist_TamperedHMAC_Dropped(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	kekHMAC := makeTestHMAC(key)

	// Create an entry with a tampered HMAC.
	entry := pkcs11.ModuleEntry{
		ModulePath: "/tmp/tampered-pkcs11.so",
		SHA256Hex:  "cafebabe",
		Vendor:     "Tampered",
		HMAC:       hex.EncodeToString(make([]byte, 32)), // all-zeros HMAC = tampered
	}

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tmpHome)
	}

	allowlistPath := filepath.Join(tmpHome, ".keylatch", "trust-allowlist.json")
	os.MkdirAll(filepath.Dir(allowlistPath), 0o700)
	data, _ := json.Marshal([]pkcs11.ModuleEntry{entry})
	os.WriteFile(allowlistPath, data, 0o600)

	entries, err := pkcs11.LoadAllowlist(kekHMAC)
	if err != nil {
		t.Fatalf("LoadAllowlist: %v", err)
	}

	// The tampered entry should be dropped.
	for _, e := range entries {
		if e.ModulePath == entry.ModulePath {
			t.Error("tampered entry was not dropped from allowlist")
		}
	}
}

func TestIsAllowed(t *testing.T) {
	entries := []pkcs11.ModuleEntry{
		{ModulePath: "/usr/lib/test.so"},
	}
	if !pkcs11.IsAllowed(entries, "/usr/lib/test.so") {
		t.Error("IsAllowed should return true for known path")
	}
	if pkcs11.IsAllowed(entries, "/usr/lib/unknown.so") {
		t.Error("IsAllowed should return false for unknown path")
	}
}

func TestVerifyModuleHash_EmptyExpected(t *testing.T) {
	// Empty expected hash = module is unpinned; must return ErrModuleHashUnpinned (M-1).
	err := pkcs11.VerifyModuleHash("/nonexistent", "")
	if !errors.Is(err, trust.ErrModuleHashUnpinned) {
		t.Errorf("empty expected hash: want ErrModuleHashUnpinned, got %v", err)
	}
}

func TestVerifyModuleHash_Mismatch(t *testing.T) {
	// Write a temp file.
	f, err := os.CreateTemp("", "pkcs11-hash-test-*.so")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	f.WriteString("not a real pkcs11 module")
	f.Close()
	defer os.Remove(f.Name())

	// Compute actual hash then pass a wrong one.
	err = pkcs11.VerifyModuleHash(f.Name(), "0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Error("VerifyModuleHash with wrong hash: expected error, got nil")
	}
}
