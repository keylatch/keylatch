//go:build darwin

// Package keychain implements the macOS Keychain backend using a dedicated
// locked keychain file (~/.keylatch/keylatch.keychain-db).
//
// Security design:
//   - Custom locked keychain (not login keychain): Layer 3 of the defense model
//   - flock serializes all operations across processes (S1-2)
//   - lock-keychain deferred immediately after unlock, runs on all paths (S1-1)
//   - Per-item ACL via RepairItemACLs (FIND3-001, S1-12)
//   - Get reads exactly one value via getOneValue (FIND3-007, S1-13)
//   - List/GetMeta read zero values (S1-6)
package keychain

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/keylatch/keylatch/internal/backend"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/runner"
)

// Options configures a KeychainBackend.
type Options struct {
	// KeychainPath is the path to the dedicated custom keychain file.
	// Defaults to ~/.keylatch/keylatch.keychain-db.
	KeychainPath string

	// LockPath is the path to the flock file for cross-process serialization.
	// Defaults to ~/.keylatch/keylatch.keychain.lock.
	LockPath string

	// SecurityBin is the absolute path to /usr/bin/security.
	// Defaults to /usr/bin/security; set to "" for auto-resolve.
	SecurityBin string

	// Runner is injectable for tests. Defaults to exec.DefaultRunner.
	Runner kexec.CommandRunner

	// Env is the environment lookup function. Defaults to llmcontext.DefaultLookup.
	Env llmcontext.Lookup
}

// KeychainBackend implements backend.Backend using a dedicated macOS keychain.
type KeychainBackend struct {
	opts        Options
	mu          sync.Mutex // protects unlocked; flock handles cross-process serialization
	unlocked    bool
	initACLOnce sync.Once //nolint:unused // planned: deferred ACL initialization gate for Phase 6
}

// Open validates options and returns an initialized KeychainBackend.
// Does NOT unlock the keychain (S1-9). Unlock is lazy, per-operation.
func Open(opts Options) (*KeychainBackend, error) {
	// Resolve defaults.
	if opts.KeychainPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("keychain: resolve home: %w", err)
		}
		opts.KeychainPath = home + "/.keylatch/keylatch.keychain-db"
	}
	if opts.LockPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("keychain: resolve home: %w", err)
		}
		opts.LockPath = home + "/.keylatch/keylatch.keychain.lock"
	}
	if opts.SecurityBin == "" {
		opts.SecurityBin = kexec.Resolve("/usr/bin/security")
		if opts.SecurityBin == "" {
			return nil, backend.ErrUnavailable
		}
	}
	if opts.Runner == nil {
		opts.Runner = kexec.DefaultRunner
	}
	if opts.Env == nil {
		opts.Env = llmcontext.DefaultLookup
	}

	// S1-9: Open does NOT unlock the keychain.
	return &KeychainBackend{opts: opts}, nil
}

// Name implements backend.Backend.
func (k *KeychainBackend) Name() string { return "keychain" }

// Capabilities implements backend.Backend.
func (k *KeychainBackend) Capabilities() []backend.Capability {
	return []backend.Capability{
		backend.CapList,
		backend.CapMetadata,
		backend.CapACL,
		backend.CapImport,
		backend.CapExport,
	}
}

// Get implements the full unlock→manifest→getOneValue→lock sequence.
//
// Sequence per architecture spec:
//  1. Check runner.OK(ctx) → ErrLocked if not approved (S1-7)
//  2. acquireFlock → defer release (S1-2)
//  3. Read unlock password from LOGIN keychain (no -k flag)
//  4. unlock-keychain -p $pw $KeychainPath
//  5. defer lock-keychain (S1-1) — registered immediately after step 4
//  6. loadManifest → resolve ManifestRow
//  7. getOneValue(row, field) — exactly one value read (FIND3-007)
//  8. Return value
func (k *KeychainBackend) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	// S1-7: check runner/gateway approval before returning plaintext.
	if !runner.OK(ctx) {
		return nil, backend.Meta{}, backend.ErrLocked
	}

	// S1-2: acquire flock for cross-process serialization.
	release, err := acquireFlock(k.opts.LockPath)
	if err != nil {
		return nil, backend.Meta{}, fmt.Errorf("keychain Get: flock: %w", err)
	}
	defer release()

	// Step 3: read unlock password from login keychain (no -k flag).
	pw, err := k.readUnlockPassword(ctx)
	if err != nil {
		return nil, backend.Meta{}, err
	}

	// Step 4: unlock the custom keychain.
	if err := k.unlockKeychain(ctx, pw); err != nil {
		return nil, backend.Meta{}, err
	}
	k.mu.Lock()
	k.unlocked = true
	k.mu.Unlock()

	// Step 5: S1-1 — defer lock-keychain IMMEDIATELY after unlock; runs on all paths.
	defer func() {
		_ = k.lockKeychain(context.Background())
		k.mu.Lock()
		k.unlocked = false
		k.mu.Unlock()
	}()

	// Step 6: load manifest.
	manifest, err := k.loadManifest(ctx)
	if err != nil {
		return nil, backend.Meta{}, err
	}

	// Resolve the ManifestRow for path.
	row, field, err := k.resolvePathToRow(manifest, path)
	if err != nil {
		return nil, backend.Meta{}, err
	}

	// Step 7: getOneValue — exactly one value read (FIND3-007).
	value, err := k.getOneValue(ctx, row, field)
	if err != nil {
		return nil, backend.Meta{}, err
	}

	meta := backend.Meta{
		Path:    path,
		Backend: "keychain",
		Version: 1,
	}

	return value, meta, nil
}

// Set stores a value in the keychain and updates the manifest.
// S1-14: per-item ACL is applied by RepairItemACLs (acl.go), called during Init and keylatch keychain repair.
func (k *KeychainBackend) Set(ctx context.Context, path string, value []byte, meta backend.Meta) error {
	release, err := acquireFlock(k.opts.LockPath)
	if err != nil {
		return fmt.Errorf("keychain Set: flock: %w", err)
	}
	defer release()

	pw, err := k.readUnlockPassword(ctx)
	if err != nil {
		return err
	}

	if err := k.unlockKeychain(ctx, pw); err != nil {
		return err
	}
	k.mu.Lock()
	k.unlocked = true
	k.mu.Unlock()
	defer func() {
		_ = k.lockKeychain(context.Background())
		k.mu.Lock()
		k.unlocked = false
		k.mu.Unlock()
	}()

	// Parse path into connection and field.
	conn, field := k.parsePathToConnField(path)

	// Add or update the generic password item.
	_, _, _, err = k.opts.Runner.Run(ctx, k.opts.SecurityBin,
		[]string{"add-generic-password",
			"-U",
			"-s", "keylatch-" + conn,
			"-a", field,
			"-w", string(value),
			"-k", k.opts.KeychainPath,
		},
		nil)
	if err != nil {
		return fmt.Errorf("keychain Set: add-generic-password: %w", err)
	}

	// Update manifest.
	manifest, err := k.loadManifest(ctx)
	if err != nil {
		return err
	}

	// Upsert the ManifestRow.
	found := false
	for i, row := range manifest.Items {
		if row.Connection == conn {
			// Add field if not present.
			hasField := false
			for _, f := range row.Fields {
				if f == field {
					hasField = true
					break
				}
			}
			if !hasField {
				manifest.Items[i].Fields = append(manifest.Items[i].Fields, field)
			}
			found = true
			break
		}
	}
	if !found {
		manifest.Items = append(manifest.Items, ManifestRow{
			Connection: conn,
			Fields:     []string{field},
		})
	}

	return k.saveManifest(ctx, manifest)
}

// Delete removes a keychain item and updates the manifest.
func (k *KeychainBackend) Delete(ctx context.Context, path string) error {
	release, err := acquireFlock(k.opts.LockPath)
	if err != nil {
		return fmt.Errorf("keychain Delete: flock: %w", err)
	}
	defer release()

	pw, err := k.readUnlockPassword(ctx)
	if err != nil {
		return err
	}

	if err := k.unlockKeychain(ctx, pw); err != nil {
		return err
	}
	k.mu.Lock()
	k.unlocked = true
	k.mu.Unlock()
	defer func() {
		_ = k.lockKeychain(context.Background())
		k.mu.Lock()
		k.unlocked = false
		k.mu.Unlock()
	}()

	manifest, err := k.loadManifest(ctx)
	if err != nil {
		return err
	}

	conn, field := k.parsePathToConnField(path)

	// Verify item exists.
	_, _, err = k.resolvePathToRowInManifest(manifest, conn, field)
	if err != nil {
		return backend.ErrNotFound
	}

	_, _, _, err = k.opts.Runner.Run(ctx, k.opts.SecurityBin,
		[]string{"delete-generic-password",
			"-s", "keylatch-" + conn,
			"-a", field,
			"-k", k.opts.KeychainPath,
		},
		nil)
	if err != nil {
		return fmt.Errorf("keychain Delete: delete-generic-password: %w", err)
	}

	// Update manifest: remove field from row; remove row if empty.
	for i, row := range manifest.Items {
		if row.Connection == conn {
			newFields := make([]string, 0, len(row.Fields))
			for _, f := range row.Fields {
				if f != field {
					newFields = append(newFields, f)
				}
			}
			if len(newFields) == 0 {
				manifest.Items = append(manifest.Items[:i], manifest.Items[i+1:]...)
			} else {
				manifest.Items[i].Fields = newFields
			}
			break
		}
	}

	return k.saveManifest(ctx, manifest)
}

// List returns metadata-only entries — zero value reads (S1-6, FIND3-007).
func (k *KeychainBackend) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	return k.listMetadata(ctx, prefix)
}

// Close locks the keychain if it was left unlocked, and releases any held flock.
func (k *KeychainBackend) Close() error {
	k.mu.Lock()
	unlocked := k.unlocked
	k.mu.Unlock()

	if unlocked {
		_ = k.lockKeychain(context.Background())
		k.mu.Lock()
		k.unlocked = false
		k.mu.Unlock()
	}
	return nil
}

// Manifest is the value-free index stored in the keychain as the item
// "keylatch-_manifest / manifest". JSON-encoded.
type Manifest struct {
	Version int           `json:"version"` // 1
	Items   []ManifestRow `json:"items"`
}

// ManifestRow describes one connection and its stored fields.
type ManifestRow struct {
	Connection string   `json:"connection"`        // e.g. "openrouter"
	Account    string   `json:"account,omitempty"` // optional multi-account disambiguator
	Fields     []string `json:"fields"`            // e.g. ["api_key", "base_url"]
}

// loadManifest reads ONLY the manifest item from the custom keychain.
// FIND3-007: does NOT read any value-bearing item. Returns empty Manifest
// (Version:1) if the manifest item does not exist yet (first run).
func (k *KeychainBackend) loadManifest(ctx context.Context) (Manifest, error) {
	stdout, stderr, exitCode, err := k.opts.Runner.Run(ctx, k.opts.SecurityBin,
		[]string{"find-generic-password",
			"-s", "keylatch-_manifest",
			"-a", "manifest",
			"-w",
			"-k", k.opts.KeychainPath,
		},
		nil)
	if err != nil {
		return Manifest{}, fmt.Errorf("keychain loadManifest: %w", err)
	}

	// Exit code 44 = errSecItemNotFound → first run, return empty manifest.
	if exitCode == 44 || (exitCode != 0 && strings.Contains(string(stderr), "could not be found")) {
		return Manifest{Version: 1, Items: []ManifestRow{}}, nil
	}
	if exitCode != 0 {
		return Manifest{}, fmt.Errorf("keychain loadManifest: security exited %d: %s", exitCode, stderr)
	}

	data := strings.TrimSpace(string(stdout))
	var m Manifest
	if err := json.Unmarshal([]byte(data), &m); err != nil {
		return Manifest{}, backend.ErrManifestCorrupt
	}
	return m, nil
}

// saveManifest writes the manifest to the keychain.
func (k *KeychainBackend) saveManifest(ctx context.Context, m Manifest) error {
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("keychain saveManifest: marshal: %w", err)
	}

	_, _, _, err = k.opts.Runner.Run(ctx, k.opts.SecurityBin,
		[]string{"add-generic-password",
			"-U",
			"-s", "keylatch-_manifest",
			"-a", "manifest",
			"-w", string(data),
			"-k", k.opts.KeychainPath,
		},
		nil)
	return err
}

// listMetadata returns Entry records from the manifest — ZERO value reads.
// FIND3-007: List and GetMeta MUST NOT read any value-bearing item.
func (k *KeychainBackend) listMetadata(ctx context.Context, prefix string) ([]backend.Entry, error) {
	manifest, err := k.loadManifest(ctx)
	if err != nil {
		return nil, err
	}

	var entries []backend.Entry
	for _, row := range manifest.Items {
		for _, field := range row.Fields {
			path := k.rowFieldToPath(row, field)
			if prefix == "" || strings.HasPrefix(path, prefix) {
				entries = append(entries, backend.Entry{
					Meta: backend.Meta{
						Path:    path,
						Backend: "keychain",
						Version: 1,
					},
					Exists: true,
				})
			}
		}
	}
	return entries, nil
}

// getOneValue retrieves exactly one value from the keychain.
// FIND3-007: exactly ONE find-generic-password call with the matching service+account.
// S1-13: Get reads exactly one value; List/GetMeta read zero.
func (k *KeychainBackend) getOneValue(ctx context.Context, row ManifestRow, field string) ([]byte, error) {
	stdout, stderr, exitCode, err := k.opts.Runner.Run(ctx, k.opts.SecurityBin,
		[]string{"find-generic-password",
			"-s", "keylatch-" + row.Connection,
			"-a", field,
			"-w",
			"-k", k.opts.KeychainPath,
		},
		nil)
	if err != nil {
		return nil, fmt.Errorf("keychain getOneValue: %w", err)
	}

	// Exit code 44 = errSecItemNotFound.
	if exitCode == 44 {
		return nil, backend.ErrNotFound
	}

	stderrStr := string(stderr)
	// errSecAuthFailed or errSecInteractionNotAllowed → ACL mismatch.
	if exitCode != 0 && (strings.Contains(stderrStr, "errSecAuthFailed") ||
		strings.Contains(stderrStr, "errSecInteractionNotAllowed") ||
		strings.Contains(stderrStr, "authorization was denied")) {
		return nil, fmt.Errorf("%w: keylatch binary path differs from stored ACL entry. Run: keylatch keychain-repair-acl", backend.ErrACLMismatch)
	}

	if exitCode != 0 {
		return nil, fmt.Errorf("keychain getOneValue: security exited %d: %s", exitCode, stderrStr)
	}

	// Trim trailing newline from security output.
	value := []byte(strings.TrimRight(string(stdout), "\n"))
	return value, nil
}

// readUnlockPassword reads the unlock password from the LOGIN keychain (no -k flag).
func (k *KeychainBackend) readUnlockPassword(ctx context.Context) (string, error) {
	stdout, stderr, exitCode, err := k.opts.Runner.Run(ctx, k.opts.SecurityBin,
		[]string{"find-generic-password",
			"-s", "keylatch-keychain",
			"-a", "unlock",
			"-w",
		},
		nil)
	if err != nil {
		return "", fmt.Errorf("keychain: read unlock password: %w", err)
	}

	stderrStr := string(stderr)
	if exitCode != 0 {
		if strings.Contains(stderrStr, "errSecAuthFailed") ||
			strings.Contains(stderrStr, "errSecInteractionNotAllowed") {
			return "", fmt.Errorf("%w: keylatch binary path differs from stored ACL entry. Run: keylatch keychain-repair-acl", backend.ErrACLMismatch)
		}
		return "", fmt.Errorf("keychain: read unlock password: security exited %d: %s", exitCode, stderrStr)
	}

	return strings.TrimRight(string(stdout), "\n"), nil
}

// unlockKeychain runs security unlock-keychain.
func (k *KeychainBackend) unlockKeychain(ctx context.Context, pw string) error {
	_, stderr, exitCode, err := k.opts.Runner.Run(ctx, k.opts.SecurityBin,
		[]string{"unlock-keychain", "-p", pw, k.opts.KeychainPath},
		nil)
	if err != nil {
		return fmt.Errorf("keychain: unlock: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("keychain: unlock-keychain exited %d: %s", exitCode, stderr)
	}
	return nil
}

// lockKeychain runs security lock-keychain.
// S1-1: ALWAYS called after unlock, even on error paths (via defer).
func (k *KeychainBackend) lockKeychain(ctx context.Context) error {
	_, _, _, err := k.opts.Runner.Run(ctx, k.opts.SecurityBin,
		[]string{"lock-keychain", k.opts.KeychainPath},
		nil)
	return err
}

// resolvePathToRow finds the ManifestRow and field name for a canonical path.
// Path format: "default/{connection}/{field}" or "{connection}/{field}".
func (k *KeychainBackend) resolvePathToRow(manifest Manifest, path string) (ManifestRow, string, error) {
	conn, field := k.parsePathToConnField(path)
	row, _, err := k.resolvePathToRowInManifest(manifest, conn, field)
	if err != nil {
		return ManifestRow{}, "", err
	}
	return row, field, nil
}

// resolvePathToRowInManifest locates a ManifestRow by connection+field.
func (k *KeychainBackend) resolvePathToRowInManifest(manifest Manifest, conn, field string) (ManifestRow, int, error) {
	for i, row := range manifest.Items {
		if row.Connection == conn {
			for _, f := range row.Fields {
				if f == field {
					return row, i, nil
				}
			}
		}
	}
	return ManifestRow{}, -1, backend.ErrNotFound
}

// parsePathToConnField parses a canonical path into (connection, field).
// Canonical path: "default/{connection}/{field}" → ("connection", "field")
// Or: "{connection}/{field}" → ("connection", "field")
func (k *KeychainBackend) parsePathToConnField(path string) (conn, field string) {
	parts := strings.Split(path, "/")
	// Strip leading "default/" namespace if present.
	if len(parts) >= 3 && parts[0] == "default" {
		parts = parts[1:]
	}
	if len(parts) >= 2 {
		conn = parts[0]
		field = strings.Join(parts[1:], "/")
		return
	}
	if len(parts) == 1 {
		conn = parts[0]
		field = parts[0]
		return
	}
	return path, path
}

// rowFieldToPath converts a ManifestRow and field into a canonical path.
func (k *KeychainBackend) rowFieldToPath(row ManifestRow, field string) string {
	return "default/" + row.Connection + "/" + field
}

// loadStore is DEPRECATED for single-key path (FIND3-007).
// RETAINED ONLY for Import/Export bulk operations that explicitly need every value.
// Use getOneValue for Get; loadManifest for List/GetMeta.
//
// Steps: flock → unlock-password → unlock-keychain → manifest → per-item reads
//
//	→ lock-keychain → flock release.
func (k *KeychainBackend) loadStore(ctx context.Context) (*backend.Store, error) { //nolint:unused // planned: batch-load path for Phase 6 manifest reads
	release, err := acquireFlock(k.opts.LockPath)
	if err != nil {
		return nil, fmt.Errorf("keychain loadStore: flock: %w", err)
	}
	defer release()

	pw, err := k.readUnlockPassword(ctx)
	if err != nil {
		return nil, err
	}

	if err := k.unlockKeychain(ctx, pw); err != nil {
		return nil, err
	}
	k.mu.Lock()
	k.unlocked = true
	k.mu.Unlock()
	// S1-1: lock-keychain deferred immediately; runs on all paths.
	defer func() {
		_ = k.lockKeychain(context.Background())
		k.mu.Lock()
		k.unlocked = false
		k.mu.Unlock()
	}()

	manifest, err := k.loadManifest(ctx)
	if err != nil {
		return nil, err
	}

	store := &backend.Store{
		Backend: "keychain",
		Entries: make(map[string][]byte),
	}

	for _, row := range manifest.Items {
		for _, field := range row.Fields {
			value, err := k.getOneValue(ctx, row, field)
			if err != nil {
				return nil, err
			}
			path := k.rowFieldToPath(row, field)
			store.Entries[path] = value
		}
	}

	return store, nil
}
