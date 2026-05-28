//go:build darwin

package keychain

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/keylatch/keylatch/internal/backend"
)

// Init implements the keychain-init CLI command lifecycle:
//  1. Generate a random 32-byte unlock password
//  2. Create the custom keychain (-p $pw)
//  3. Store the unlock password in the LOGIN keychain with -T {binaryPath}
//  4. Set keychain to never auto-lock
//  5. Call RepairACL to bind the ACL to code-signing identity
//  6. Set a canary entry to validate the keychain is writable
//  7. Call RepairItemACLs
//
// Idempotent: running Init twice on the same path does not corrupt the keychain.
func (k *KeychainBackend) Init(ctx context.Context, service string) error {
	// Step 1: generate random 32-byte unlock password (base64-encoded for ASCII safety).
	var pwRaw [32]byte
	if _, err := rand.Read(pwRaw[:]); err != nil {
		return fmt.Errorf("keychain Init: generate password: %w", err)
	}
	pw := base64.URLEncoding.EncodeToString(pwRaw[:])
	// Zeroize the raw password bytes on return.
	defer func() {
		for i := range pwRaw {
			pwRaw[i] = 0
		}
	}()

	currentBin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("keychain Init: os.Executable: %w", err)
	}

	// Ensure the keylatch directory exists.
	keylatchDir := homeDir() + "/.keylatch"
	if err := os.MkdirAll(keylatchDir, 0o700); err != nil {
		return fmt.Errorf("keychain Init: mkdir %q: %w", keylatchDir, err)
	}

	// Step 2: create the custom keychain (skip if already exists).
	_, _, exitCode, err := k.opts.Runner.Run(ctx, k.opts.SecurityBin,
		[]string{"create-keychain", "-p", pw, k.opts.KeychainPath},
		nil)
	if err != nil {
		return fmt.Errorf("keychain Init: create-keychain: %w", err)
	}
	if exitCode != 0 {
		// exit code 48 = errSecDuplicateKeychain — keychain already exists, continue.
		if exitCode != 48 {
			return fmt.Errorf("keychain Init: create-keychain failed (exit %d)", exitCode)
		}
		// already exists — proceed normally
	}

	// Step 3: store unlock password in LOGIN keychain (no -k flag) with -T {binaryPath}.
	_, _, _, err = k.opts.Runner.Run(ctx, k.opts.SecurityBin,
		[]string{"add-generic-password",
			"-U",
			"-s", "keylatch-keychain",
			"-a", "unlock",
			"-w", pw,
			"-T", currentBin,
		},
		nil)
	if err != nil {
		return fmt.Errorf("keychain Init: store unlock password: %w", err)
	}

	// Step 4: set keychain to never auto-lock.
	_, _, _, err = k.opts.Runner.Run(ctx, k.opts.SecurityBin,
		[]string{"set-keychain-settings", "-lut", "0", k.opts.KeychainPath},
		nil)
	if err != nil {
		return fmt.Errorf("keychain Init: set-keychain-settings: %w", err)
	}

	// Step 5: RepairACL to bind ACL to code-signing identity (FIND-013).
	if err := k.RepairACL(ctx); err != nil {
		// Non-fatal in Phase 1 — log but continue.
		slog.Warn("keychain RepairACL failed", "error", err)
	}

	// Step 6: validate keychain is writable with a canary entry.
	canaryPath := "default/__init__/canary"
	meta := backend.Meta{Path: canaryPath, Backend: "keychain", Version: 1}
	if err := k.Set(ctx, canaryPath, []byte("keylatch-init-ok"), meta); err != nil {
		return fmt.Errorf("keychain Init: write canary entry: %w", err)
	}

	// Step 7: RepairItemACLs for per-item ACL enforcement (FIND3-001).
	if err := k.RepairItemACLs(ctx); err != nil {
		return fmt.Errorf("keychain Init: RepairItemACLs: %w", err)
	}

	return nil
}

// homeDir returns the user's home directory, falling back to "" on error.
func homeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

// zeroizeString zeroes a string's backing bytes (unsafe but useful for passwords).
// For Phase 1, we accept the limitation of Go's string immutability.
//
//nolint:unused // planned: called during keychain shutdown when session cleanup is added
func zeroizeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// trimNewline trims a trailing newline from a byte slice.
//
//nolint:unused // planned: used when parsing security binary output in Phase 6
func trimNewline(b []byte) string {
	return strings.TrimRight(string(b), "\n")
}
