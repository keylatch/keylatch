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

// Init implements the keychain-init CLI command lifecycle. It is safe to run
// repeatedly (e.g. on setup re-run): it never generates a new unlock
// password when a usable one already exists.
//
//  1. Read the existing login-keychain unlock item (if any) BEFORE deciding
//     whether to generate a password.
//  2. If both the unlock item and the custom keychain-db already exist and
//     the item's password successfully unlocks the db, Init is a verify/
//     no-op: the existing password is reused, the login-keychain unlock
//     item is left untouched, and only the ACL/canary/item-ACL repair steps
//     run.
//  3. If only the unlock item exists (no keychain-db yet — e.g. a fresh
//     install that inherited a stale login-keychain item), the existing
//     password is reused to create the new, currently-empty keychain-db.
//     Nothing is at risk of being orphaned because no keychain-db exists yet.
//  4. If neither exists, this is a genuine first run: a new random password
//     is generated.
//  5. Any other combination (an unlock item that does not unlock the
//     existing keychain-db, or a keychain-db with no unlock item at all)
//     means the stored password has already been lost or the two are out of
//     sync. Init refuses to generate a replacement password in that case —
//     doing so would silently overwrite the login-keychain unlock item and
//     permanently orphan any secrets already stored under the old one (the
//     original C1 data-loss bug). Call ForceReinit to proceed anyway after
//     the caller has confirmed the user accepts losing access to existing
//     secrets.
func (k *KeychainBackend) Init(ctx context.Context, service string) error {
	return k.init(ctx, service, false)
}

// ForceReinit re-initializes the keychain unconditionally: it always
// generates a brand-new random unlock password and overwrites the
// login-keychain unlock item, even if a keychain-db and/or a working unlock
// item already exist. Any secrets stored under the previous password become
// permanently unrecoverable. Callers MUST have already obtained explicit
// user confirmation of this data loss (see `keylatch keychain-init --force`).
func (k *KeychainBackend) ForceReinit(ctx context.Context, service string) error {
	return k.init(ctx, service, true)
}

// init is the shared Init/ForceReinit implementation. See Init's doc comment
// for the decision table; force short-circuits the two refusal branches.
func (k *KeychainBackend) init(ctx context.Context, service string, force bool) error {
	dbExists := k.keychainDBExists()
	existingPW, hasUnlockItem, err := k.tryReadUnlockPassword(ctx)
	if err != nil {
		return fmt.Errorf("keychain Init: check existing unlock item: %w", err)
	}

	switch {
	case hasUnlockItem && dbExists:
		if unlockErr := k.unlockKeychain(ctx, existingPW); unlockErr == nil {
			// The stored password still unlocks the existing keychain-db —
			// nothing to regenerate. Lock back immediately (this was only a
			// verification probe) and finish with the existing password,
			// leaving the login-keychain unlock item untouched.
			_ = k.lockKeychain(ctx)
			return k.finishInit(ctx, service, existingPW, false)
		}
		if !force {
			return fmt.Errorf(
				"keychain Init: an unlock item exists in the login keychain but does not unlock %s — "+
					"refusing to generate a new password (this would permanently orphan any secrets "+
					"already stored under the current one). Run `keylatch keychain-init --force` only "+
					"after confirming you accept losing access to existing secrets",
				k.opts.KeychainPath)
		}
		// force=true: fall through to generate a fresh password below.
	case hasUnlockItem && !dbExists:
		// Stale unlock item with no keychain-db behind it yet — reusing the
		// existing password is safe because there is no existing data that
		// could be orphaned.
		return k.finishInit(ctx, service, existingPW, true)
	case !hasUnlockItem && dbExists:
		if !force {
			return fmt.Errorf(
				"keychain Init: %s already exists but no unlock item was found in the login keychain — "+
					"refusing to generate a new password (this would permanently orphan any secrets "+
					"already stored). Run `keylatch keychain-init --force` only after confirming you "+
					"accept losing access to existing secrets",
				k.opts.KeychainPath)
		}
		// force=true: fall through to generate a fresh password below.
	default:
		// Neither the keychain-db nor an unlock item exists: genuine first
		// run — fall through to generate a fresh password below.
	}

	// Generate a random 32-byte unlock password (base64-encoded for ASCII
	// safety). Only reached on a genuine first run, or force=true after an
	// explicit data-loss confirmation by the caller.
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

	return k.finishInit(ctx, service, pw, true)
}

// finishInit runs the remaining Init steps using pw as the already-decided
// unlock password: it creates the keychain-db if needed, optionally
// (re)writes the login-keychain unlock item, disables auto-lock, repairs the
// ACL, and validates writability with a canary entry.
//
// writeUnlockItem is false only on the "verified existing password" path in
// init — every other caller passes true because either nothing exists yet
// (nothing to overwrite) or the caller has forced an explicit reset.
func (k *KeychainBackend) finishInit(ctx context.Context, _ string, pw string, writeUnlockItem bool) error {
	currentBin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("keychain Init: os.Executable: %w", err)
	}

	// Ensure the keylatch directory exists.
	keylatchDir := homeDir() + "/.keylatch"
	if err := os.MkdirAll(keylatchDir, 0o700); err != nil {
		return fmt.Errorf("keychain Init: mkdir %q: %w", keylatchDir, err)
	}

	// Create the custom keychain (skip if already exists).
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

	// Store the unlock password in the LOGIN keychain (no -k flag) with
	// -T {binaryPath}, but only when the caller determined this is safe —
	// see the decision table in Init's doc comment. When writeUnlockItem is
	// false, an already-verified existing item is left untouched.
	if writeUnlockItem {
		_, stderr, exitCode, err := k.opts.Runner.Run(ctx, k.opts.SecurityBin,
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
		if exitCode != 0 {
			return fmt.Errorf("keychain Init: store unlock password: security exited %d: %s", exitCode, strings.TrimSpace(string(stderr)))
		}
	}

	// Set keychain to never auto-lock.
	_, _, _, err = k.opts.Runner.Run(ctx, k.opts.SecurityBin,
		[]string{"set-keychain-settings", "-lut", "0", k.opts.KeychainPath},
		nil)
	if err != nil {
		return fmt.Errorf("keychain Init: set-keychain-settings: %w", err)
	}

	// RepairACL to bind ACL to code-signing identity.
	if err := k.RepairACL(ctx); err != nil {
		// Non-fatal — log but continue.
		slog.Warn("keychain RepairACL failed", "error", err)
	}

	// Validate keychain is writable with a canary entry.
	canaryPath := "default/__init__/canary"
	meta := backend.Meta{Path: canaryPath, Backend: "keychain", Version: 1}
	if err := k.Set(ctx, canaryPath, []byte("keylatch-init-ok"), meta); err != nil {
		return fmt.Errorf("keychain Init: write canary entry: %w", err)
	}

	// RepairItemACLs for per-item ACL enforcement.
	if err := k.RepairItemACLs(ctx); err != nil {
		return fmt.Errorf("keychain Init: RepairItemACLs: %w", err)
	}

	return nil
}

// keychainDBExists reports whether the custom keychain-db file is already
// present on disk.
func (k *KeychainBackend) keychainDBExists() bool {
	_, statErr := os.Stat(k.opts.KeychainPath)
	return statErr == nil
}

// tryReadUnlockPassword attempts to read the existing login-keychain unlock
// item. Unlike readUnlockPassword (keychain.go), it treats "not found" (or
// any other non-zero exit) as a normal, expected outcome — exists=false,
// err=nil — rather than an error, since Init's job is only to decide whether
// a reusable password already exists.
func (k *KeychainBackend) tryReadUnlockPassword(ctx context.Context) (pw string, exists bool, err error) {
	stdout, _, exitCode, runErr := k.opts.Runner.Run(ctx, k.opts.SecurityBin,
		[]string{"find-generic-password",
			"-s", "keylatch-keychain",
			"-a", "unlock",
			"-w",
		},
		nil)
	if runErr != nil {
		return "", false, fmt.Errorf("security find-generic-password: %w", runErr)
	}
	if exitCode != 0 {
		return "", false, nil
	}
	return strings.TrimRight(string(stdout), "\n"), true, nil
}

// homeDir returns the user's home directory, falling back to "" on error.
func homeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

// zeroizeBytes zeroes a byte slice's contents in place (best-effort; unsafe
// but useful for scrubbing password/secret buffers before they go out of scope).
//
//nolint:unused // planned: called during keychain shutdown when session cleanup is added
func zeroizeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// trimNewline trims a trailing newline from a byte slice.
//
//nolint:unused // planned: used when parsing security binary output
func trimNewline(b []byte) string {
	return strings.TrimRight(string(b), "\n")
}
