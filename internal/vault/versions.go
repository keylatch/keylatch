// Package vault implements the keylatch secret vault with versioned metadata
// and version management. All functions are value-free — MUST NEVER call
// backend.Get.
package vault

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
	vpath "github.com/keylatch/keylatch/internal/vault/path"
)

// Vault error sentinels for version operations.
var (
	ErrVersionNotFound       = errors.New("vault: version not found")
	ErrVersionDestroyed      = errors.New("vault: version is destroyed")
	ErrVersionDeleted        = errors.New("vault: version is soft-deleted (rollback first)")
	ErrDestroyCurrentVersion = errors.New("vault: cannot destroy the current version (rotate first)")
)

// defaultCategoryResolver wraps the registry's Get function.
func defaultCategoryResolver(provider string) (string, error) {
	// Import here is intentional: avoid circular import by importing only
	// the registry at the vault layer, not at the meta/path layer.
	// registry.Get returns (ConnectionTemplate, error); we extract Category.
	// If provider not found, return ErrUnknownProvider.
	return resolveCategory(provider)
}

// GetMeta returns value-free metadata for a canonical path.
//
// Security invariant: MUST NOT call backend.Get.
func GetMeta(ctx context.Context, path string, cfg config.Config, env llmcontext.Lookup) (vmeta.Meta, error) {
	canonical, err := canonicalizePath(path, cfg, env)
	if err != nil {
		return vmeta.Meta{}, err
	}

	b, err := dispatch.Select(ctx, cfg, env)
	if err != nil {
		return vmeta.Meta{}, err
	}

	return b.GetMeta(ctx, canonical)
}

// SetMeta validates and writes value-free metadata for a path.
// Updates UpdatedAt to time.Now() before writing.
//
// Security invariant: MUST NOT call backend.Get.
func SetMeta(ctx context.Context, path string, m vmeta.Meta, cfg config.Config, env llmcontext.Lookup) error {
	canonical, err := canonicalizePath(path, cfg, env)
	if err != nil {
		return err
	}

	m.Path = canonical
	m.UpdatedAt = time.Now()

	if err := m.Validate(); err != nil {
		return err
	}

	b, err := dispatch.Select(ctx, cfg, env)
	if err != nil {
		return err
	}

	return b.SetMeta(ctx, canonical, m)
}

// ListMeta returns value-free metadata for all paths matching the given prefix.
// Empty prefix returns all metadata. Results are sorted by Meta.Path.
//
// Security invariant: MUST NOT call backend.Get.
// Canary invariant: output must never contain KEYLATCH_CANARY_PHASE4_LIST_0xDEADBEEF.
func ListMeta(ctx context.Context, prefix string, cfg config.Config, env llmcontext.Lookup) ([]vmeta.Meta, error) {
	b, err := dispatch.Select(ctx, cfg, env)
	if err != nil {
		return nil, err
	}

	metas, err := b.ListMeta(ctx, prefix)
	if err != nil {
		return nil, err
	}

	sort.Slice(metas, func(i, j int) bool {
		return metas[i].Path < metas[j].Path
	})
	return metas, nil
}

// RotateValue writes a new encrypted value version and updates metadata.
// This is the canonical write path for versioned values. It atomically:
//  1. Loads existing metadata (or initializes if new)
//  2. Increments version counter
//  3. Builds an AADBinding
//  4. Writes the versioned value via backend.SetVersioned
//  5. Merges caller-supplied metadata fields
//  6. Enforces MaxVersions (soft-deletes oldest)
//  7. Writes updated metadata
//
// Returns the new version number.
//
// Security invariant: does NOT call backend.Get.
func RotateValue(
	ctx context.Context,
	path string,
	value []byte,
	m vmeta.Meta,
	cfg config.Config,
	env llmcontext.Lookup,
) (int, error) {
	canonical, err := canonicalizePath(path, cfg, env)
	if err != nil {
		return 0, err
	}

	b, err := dispatch.Select(ctx, cfg, env)
	if err != nil {
		return 0, err
	}

	// Step 1: Load existing metadata or initialize for a new path.
	now := time.Now()
	existing, err := b.GetMeta(ctx, canonical)
	if err != nil {
		if !errors.Is(err, backend.ErrNotFound) {
			return 0, fmt.Errorf("vault: RotateValue GetMeta: %w", err)
		}
		// New path — initialize metadata.
		existing = vmeta.Meta{
			SchemaVersion:  vmeta.CurrentSchemaVersion,
			Path:           canonical,
			Accessor:       vmeta.NewAccessor(),
			Backend:        b.Name(),
			CurrentVersion: 0,
			OldestVersion:  1,
			MaxVersions:    vmeta.DefaultMaxVersions,
			CreatedAt:      now,
		}
	}

	// Step 2: Increment version.
	newVersion := existing.CurrentVersion + 1

	// Step 3: Build AADBinding.
	parts, err := vpath.Parts(canonical)
	if err != nil {
		return 0, fmt.Errorf("vault: RotateValue Parts: %w", err)
	}

	// Attempt to obtain the active key term from the backend.
	// Backends that do not support key terms return 0 (plaintext mode).
	activeKeyTerm := 0
	if ktp, ok := b.(interface{ ActiveKeyTerm() (int, error) }); ok {
		if term, terr := ktp.ActiveKeyTerm(); terr == nil {
			activeKeyTerm = term
		}
	}

	aad := vmeta.AADBinding{
		SchemaVersion: vmeta.CurrentSchemaVersion,
		Namespace:     parts.Namespace,
		Path:          canonical,
		Version:       newVersion,
		KeyTerm:       activeKeyTerm,
		BackendID:     b.ID(),
		CreatedAt:     now,
		Algorithm:     "xchacha20-poly1305",
	}

	// Step 4: Write versioned value.
	if err := b.SetVersioned(ctx, canonical, newVersion, value); err != nil {
		return 0, fmt.Errorf("vault: RotateValue SetVersioned: %w", err)
	}

	// Steps 5–10: Merge caller metadata and update version list.
	vm := vmeta.VersionMeta{
		Version:   newVersion,
		CreatedAt: now,
		CreatedBy: m.Owner,
		ExpiresAt: m.ExpiresAt,
		AAD:       aad,
	}

	// Merge caller-supplied fields (metadata round-trip fields).
	if m.Owner != "" {
		existing.Owner = m.Owner
	}
	if m.Scope != "" {
		existing.Scope = m.Scope
	}
	if m.Purpose != "" {
		existing.Purpose = m.Purpose
	}
	if m.RotationHint != "" {
		existing.RotationHint = m.RotationHint
	}
	if m.IssuedAt != nil {
		existing.IssuedAt = m.IssuedAt
	}
	if m.ExpiresAt != nil {
		existing.ExpiresAt = m.ExpiresAt
	}
	if len(m.SafeFields) > 0 {
		existing.SafeFields = m.SafeFields
	}
	if len(m.Custom) > 0 {
		if existing.Custom == nil {
			existing.Custom = make(map[string]string)
		}
		for k, v := range m.Custom {
			existing.Custom[k] = v
		}
	}
	if m.TeamID != "" {
		existing.TeamID = m.TeamID
	}
	if len(m.SharedRecipients) > 0 {
		existing.SharedRecipients = m.SharedRecipients
	}
	if m.MaxVersions > 0 {
		existing.MaxVersions = m.MaxVersions
	}

	existing.CurrentVersion = newVersion
	existing.UpdatedAt = now
	existing.Versions = append(existing.Versions, vm)

	// Step 11: MaxVersions enforcement.
	// MaxVersions enforcement: evicts exactly one version per rotation.
	// If MaxVersions was reduced below the current version count mid-flight,
	// convergence is gradual (one eviction per rotate call), not immediate.
	if existing.MaxVersions > 0 && len(existing.Versions) > existing.MaxVersions {
		oldest := &existing.Versions[0]
		deletedNow := now
		oldest.DeletedAt = &deletedNow
		oldestVersion := oldest.Version

		// Best-effort delete of ciphertext.
		_ = b.DeleteVersioned(ctx, canonical, oldestVersion)

		existing.OldestVersion = existing.Versions[1].Version
		existing.Versions = existing.Versions[1:]
	}

	// Step 12: Write updated metadata.
	setMetaErr := b.SetMeta(ctx, canonical, existing)
	if setMetaErr != nil {
		// Best-effort compensation: remove the orphaned value file.
		_ = b.DeleteVersioned(ctx, canonical, newVersion)
		return 0, fmt.Errorf("vault: RotateValue SetMeta: %w", setMetaErr)
	}

	// Emit ActionWrite audit event after successful write (mirrors vault.Set).
	// Credential value bytes are NEVER included in the event (S-RM-9).
	emitVaultEvent(ctx, audit.Event{
		Timestamp: now,
		Action:    audit.ActionWrite,
		Outcome:   audit.OutcomeOK,
		Path:      canonical,
	})

	return newVersion, nil
}

// GetVersion returns the raw bytes and version metadata for a specific version.
// Returns ErrVersionNotFound, ErrVersionDestroyed, or ErrVersionDeleted as appropriate.
//
// Security invariant: does NOT call backend.Get (calls backend.GetVersioned).
func GetVersion(
	ctx context.Context,
	path string,
	version int,
	cfg config.Config,
	env llmcontext.Lookup,
) ([]byte, vmeta.VersionMeta, error) {
	canonical, err := canonicalizePath(path, cfg, env)
	if err != nil {
		return nil, vmeta.VersionMeta{}, err
	}

	b, err := dispatch.Select(ctx, cfg, env)
	if err != nil {
		return nil, vmeta.VersionMeta{}, err
	}

	m, err := b.GetMeta(ctx, canonical)
	if err != nil {
		return nil, vmeta.VersionMeta{}, err
	}

	vm, found := findVersion(m, version)
	if !found {
		return nil, vmeta.VersionMeta{}, ErrVersionNotFound
	}

	// Security invariant: metadata-layer block takes precedence over
	// physical file presence.
	if vm.DestroyedAt != nil {
		return nil, vmeta.VersionMeta{}, ErrVersionDestroyed
	}
	if vm.DeletedAt != nil {
		return nil, vmeta.VersionMeta{}, ErrVersionDeleted
	}

	value, err := b.GetVersioned(ctx, canonical, version)
	if err != nil {
		return nil, vmeta.VersionMeta{}, err
	}
	return value, vm, nil
}

// DestroyVersion permanently marks a version as destroyed and attempts to
// delete its ciphertext file. The metadata-layer block is enforced even if
// the physical file persists.
//
// Returns ErrDestroyCurrentVersion if caller tries to destroy the current version.
// Security invariant: caller must check IsLLMSession before calling.
func DestroyVersion(
	ctx context.Context,
	path string,
	version int,
	cfg config.Config,
	env llmcontext.Lookup,
) error {
	canonical, err := canonicalizePath(path, cfg, env)
	if err != nil {
		return err
	}

	b, err := dispatch.Select(ctx, cfg, env)
	if err != nil {
		return err
	}

	m, err := b.GetMeta(ctx, canonical)
	if err != nil {
		return err
	}

	idx, found := findVersionIdx(m, version)
	if !found {
		return ErrVersionNotFound
	}

	vm := &m.Versions[idx]
	if vm.DestroyedAt != nil {
		return ErrVersionDestroyed
	}

	// Cannot destroy the current version — caller must rotate first.
	if version == m.CurrentVersion {
		return ErrDestroyCurrentVersion
	}

	// Best-effort physical delete.
	_ = b.DeleteVersioned(ctx, canonical, version)

	// Metadata-layer block: always set DestroyedAt regardless of whether
	// the physical delete succeeded.
	now := time.Now()
	vm.DestroyedAt = &now
	m.DestroyedVersions = append(m.DestroyedVersions, version)
	m.UpdatedAt = now

	return b.SetMeta(ctx, canonical, m)
}

// Rollback creates a new version with the same plaintext as an older version.
// Version numbers are monotonically increasing; rollback never moves a pointer.
// The new version's Custom map includes "rolled_back_from" = strconv.Itoa(version).
//
// Security invariant: caller must check IsLLMSession before calling.
func Rollback(
	ctx context.Context,
	path string,
	version int,
	cfg config.Config,
	env llmcontext.Lookup,
) error {
	canonical, err := canonicalizePath(path, cfg, env)
	if err != nil {
		return err
	}

	b, err := dispatch.Select(ctx, cfg, env)
	if err != nil {
		return err
	}

	m, err := b.GetMeta(ctx, canonical)
	if err != nil {
		return err
	}

	vm, found := findVersion(m, version)
	if !found {
		return ErrVersionNotFound
	}

	if vm.DestroyedAt != nil {
		return ErrVersionDestroyed
	}
	if vm.DeletedAt != nil {
		return ErrVersionDeleted
	}

	// Read plaintext via versioned storage (not backend.Get).
	plaintext, err := b.GetVersioned(ctx, canonical, version)
	if err != nil {
		return fmt.Errorf("vault: Rollback GetVersioned: %w", err)
	}

	// Build partial meta to pass through RotateValue.
	partial := vmeta.Meta{
		Custom: map[string]string{
			"rolled_back_from": strconv.Itoa(version),
		},
	}

	_, err = RotateValue(ctx, canonical, plaintext, partial, cfg, env)
	return err
}

// canonicalizePath resolves a possibly-shorthand path to canonical form.
// Uses the default namespace "default" if not specified.
func canonicalizePath(path string, _ config.Config, _ llmcontext.Lookup) (string, error) {
	defaults := vpath.Defaults{Namespace: "default"}
	canonical, err := vpath.Canonicalize(path, defaults, defaultCategoryResolver)
	if err != nil {
		// If it fails canonicalization, try to use it directly (already canonical).
		// A fully canonical path passes Canonicalize unchanged.
		return "", fmt.Errorf("vault: canonicalize %q: %w", path, err)
	}
	return canonical, nil
}

// findVersion searches for a version in m.Versions by version number.
func findVersion(m vmeta.Meta, version int) (vmeta.VersionMeta, bool) {
	for _, vm := range m.Versions {
		if vm.Version == version {
			return vm, true
		}
	}
	return vmeta.VersionMeta{}, false
}

// findVersionIdx returns the index of the version in m.Versions.
func findVersionIdx(m vmeta.Meta, version int) (int, bool) {
	for i, vm := range m.Versions {
		if vm.Version == version {
			return i, true
		}
	}
	return 0, false
}
