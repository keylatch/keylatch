package file

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

// afterValueWriteHook is an injectable test hook called after SetVersioned
// succeeds but before SetMeta is called. Tests use this to simulate a crash
// between the two writes. nil in production.
var afterValueWriteHook func() error

// SetAfterValueWriteHook sets a test hook that fires after SetVersioned succeeds
// but before SetMeta is called during migration. Pass nil to clear the hook.
// This is an exported hook so test files can inject crashes.
func SetAfterValueWriteHook(err error) {
	if err == nil {
		afterValueWriteHook = nil
	} else {
		afterValueWriteHook = func() error { return err }
	}
}

// MigrateIfFlat is the exported wrapper around migrateIfFlat for testing.
func (fb *FileBackend) MigrateIfFlat(ctx context.Context, canonical string) error {
	return fb.migrateIfFlat(ctx, canonical)
}

// migrateIfFlat migrates a legacy flat-layout secret to the versioned
// layout when the flat file exists but the versioned value file does not.
//
// The flat layout stored secrets as: <root>/<canonical>/value.enc
// The versioned layout uses:
//
//	<root>/values/<canonical>/1    — version 1 value
//	<root>/metadata/<canonical>.json — metadata
//
// Security invariant: if SetVersioned succeeds but SetMeta fails, the
// new versioned file is removed and the old flat file is left intact for the
// next call to retry.
func (fb *FileBackend) migrateIfFlat(ctx context.Context, canonical string) error {
	// Check if the versioned layout already exists — no migration needed.
	vp := valuePath(fb.dir, canonical, 1)
	if _, err := os.Stat(vp); err == nil {
		return nil // already migrated
	}

	// Check if the old flat file exists.
	flatPath := filepath.Join(fb.dir, filepath.FromSlash(canonical), "value.enc")
	fi, err := os.Stat(flatPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no flat file either — nothing to migrate
		}
		return fmt.Errorf("migrate: stat flat file: %w", err)
	}

	createdAt := fi.ModTime()

	// Read the flat file.
	oldValue, err := os.ReadFile(flatPath)
	if err != nil {
		return fmt.Errorf("migrate: read flat file: %w", err)
	}

	now := time.Now()

	// Write the versioned value record.
	if err := fb.SetVersioned(ctx, canonical, 1, oldValue); err != nil {
		return fmt.Errorf("migrate: SetVersioned: %w", err)
	}

	// Test hook: simulate crash between SetVersioned and SetMeta.
	if afterValueWriteHook != nil {
		if hookErr := afterValueWriteHook(); hookErr != nil {
			// Compensate: remove the newly written versioned file so the old
			// flat file remains as the source of truth.
			_ = os.Remove(vp)
			return fmt.Errorf("migrate: aborted by test hook: %w", hookErr)
		}
	}

	// Build metadata for the migrated entry.
	m := vmeta.Meta{
		SchemaVersion:  vmeta.CurrentSchemaVersion,
		Path:           canonical,
		Accessor:       vmeta.NewAccessor(),
		Backend:        "file",
		CurrentVersion: 1,
		OldestVersion:  1,
		MaxVersions:    vmeta.DefaultMaxVersions,
		CreatedAt:      createdAt,
		UpdatedAt:      now,
		Versions: []vmeta.VersionMeta{
			{
				Version:   1,
				CreatedAt: createdAt,
			},
		},
	}

	if err := fb.SetMeta(ctx, canonical, m); err != nil {
		// Compensate: remove the new versioned file; leave flat file intact.
		_ = os.Remove(vp)
		return fmt.Errorf("migrate: SetMeta: %w", err)
	}

	// Remove the old flat file. If this fails, log a warning but return nil —
	// the migration is effectively complete (idempotent: next call will skip
	// because valuePath/1 now exists).
	if err := os.Remove(flatPath); err != nil && !os.IsNotExist(err) {
		// Non-fatal: log and continue.
		_ = err // production code would log here; structured logging is not yet wired up
	}

	return nil
}
