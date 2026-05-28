// Package pkcs11 implements a trust.RootOfTrust adapter backed by PKCS#11 tokens.
// Module path validation via a SHA-256 allowlist is enforced before any session is opened.
package pkcs11

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/keylatch/keylatch/internal/trust"
)

// ModuleEntry is a single PKCS#11 module allowlist entry.
type ModuleEntry struct {
	// ModulePath is the absolute path to the PKCS#11 shared library.
	ModulePath string `json:"module_path"`
	// SHA256Hex is the expected SHA-256 hex digest of the on-disk binary.
	SHA256Hex string `json:"sha256"`
	// Vendor is a human-readable vendor label (value-free).
	Vendor string `json:"vendor"`
	// HMAC is the HMAC of (ModulePath + ":" + SHA256Hex) under the KEK HMAC key.
	// Prevents tampering with the allowlist file.
	HMAC string `json:"hmac"`
}

// defaultPKCS11Allowlist contains trusted PKCS#11 modules distributed by known vendors.
// The SHA256Hex field is intentionally empty in this default list — real deployments
// must populate it via `keylatch trust allowlist add`.
var defaultPKCS11Allowlist = []ModuleEntry{
	{ModulePath: "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", Vendor: "OpenSC"},
	{ModulePath: "/usr/lib/softhsm/libsofthsm2.so", Vendor: "SoftHSM2"},
	{ModulePath: "/usr/local/lib/libsofthsm2.so", Vendor: "SoftHSM2"},
	{ModulePath: "/usr/lib/ykcs11.dylib", Vendor: "YubiKey"},
	{ModulePath: "/usr/lib/x86_64-linux-gnu/libykcs11.so", Vendor: "YubiKey"},
	{ModulePath: "/usr/local/lib/opensc-pkcs11.dylib", Vendor: "OpenSC"},
}

// userAllowlistPath returns the path to the user-managed allowlist file.
func userAllowlistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".keylatch", "trust-allowlist.json")
}

// LoadAllowlist reads the user-managed allowlist at ~/.keylatch/trust-allowlist.json
// and returns a merged list with the default entries.
//
// kekHMAC computes an HMAC tag for an input byte slice using the current KEK's HMAC key.
// Entries with an invalid HMAC are silently dropped (caller should emit audit warn).
func LoadAllowlist(kekHMAC func([]byte) []byte) ([]ModuleEntry, error) {
	entries := make([]ModuleEntry, len(defaultPKCS11Allowlist))
	copy(entries, defaultPKCS11Allowlist)

	path := userAllowlistPath()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return entries, nil
	}
	if err != nil {
		return entries, fmt.Errorf("pkcs11: read allowlist: %w", err)
	}

	var userEntries []ModuleEntry
	if err := json.Unmarshal(data, &userEntries); err != nil {
		return entries, fmt.Errorf("pkcs11: parse allowlist: %w", err)
	}

	for _, e := range userEntries {
		if !verifyEntryHMAC(e, kekHMAC) {
			// Drop silently; caller should emit audit warn.
			continue
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// verifyEntryHMAC checks that e.HMAC equals HMAC(kekHMAC, e.ModulePath+":"+e.SHA256Hex).
func verifyEntryHMAC(e ModuleEntry, kekHMAC func([]byte) []byte) bool {
	if kekHMAC == nil || e.HMAC == "" {
		return false
	}
	input := []byte(e.ModulePath + ":" + e.SHA256Hex)
	expected := kekHMAC(input)
	actual, err := hex.DecodeString(e.HMAC)
	if err != nil {
		return false
	}
	return hmac.Equal(expected, actual)
}

// VerifyModuleHash computes the SHA-256 hash of the on-disk module at path
// and compares it to expectedHex (hex-encoded). Returns ErrModuleHashMismatch on mismatch.
// If expectedHex is empty, returns ErrModuleHashUnpinned to signal that hash pinning is not
// configured (callers should emit a warning but may still proceed).
func VerifyModuleHash(path, expectedHex string) error {
	if expectedHex == "" {
		return trust.ErrModuleHashUnpinned
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("pkcs11: open module %q: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // defer close in read-only hash path

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("pkcs11: hash module %q: %w", path, err)
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actual, expectedHex) {
		return fmt.Errorf("pkcs11 module %q: %w (got %s, want %s)", path, trust.ErrModuleHashMismatch, actual, expectedHex)
	}
	return nil
}

// IsAllowed returns true if path appears in the provided entries list.
func IsAllowed(entries []ModuleEntry, path string) bool {
	for _, e := range entries {
		if e.ModulePath == path {
			return true
		}
	}
	return false
}

// MakeEntryHMAC computes the HMAC for a new allowlist entry.
func MakeEntryHMAC(e ModuleEntry, kekHMAC func([]byte) []byte) string {
	input := []byte(e.ModulePath + ":" + e.SHA256Hex)
	h := kekHMAC(input)
	return hex.EncodeToString(h)
}

// ComputeModuleHash computes the SHA-256 hex hash of the file at path.
func ComputeModuleHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("pkcs11: open: %w", err)
	}
	defer f.Close() //nolint:errcheck // defer close in read-only hash path
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("pkcs11: hash: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SaveAllowlist writes user entries to the user allowlist file.
// Only user-added entries (not defaults) are persisted.
func SaveAllowlist(userEntries []ModuleEntry) error {
	path := userAllowlistPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("pkcs11: mkdir: %w", err)
	}
	data, err := json.MarshalIndent(userEntries, "", "  ")
	if err != nil {
		return fmt.Errorf("pkcs11: marshal: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("pkcs11: write allowlist: %w", err)
	}
	return os.Chmod(path, 0o600)
}
