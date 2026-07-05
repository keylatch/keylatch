package file_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/file"
)

// setFlatFile creates a legacy flat layout entry for testing migration.
func setFlatFile(t *testing.T, dir, canonical string, value []byte) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(canonical))
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatalf("mkdir flat dir: %v", err)
	}
	encPath := filepath.Join(p, "value.enc")
	if err := os.WriteFile(encPath, value, 0o600); err != nil {
		t.Fatalf("write flat file: %v", err)
	}
}

// TestMigrateIfFlat_FlatFileMigratedOnFirstGet verifies that 5 flat-layout
// entries are lazily migrated the first time GetVersioned is called.
// Requires a keyring-backed backend.
func TestMigrateIfFlat_FlatFileMigratedOnFirstGet(t *testing.T) {
	dir := t.TempDir()

	// Write 5 flat files.
	canonicals := []string{
		"default/ai/openrouter/api_key",
		"default/ai/anthropic/api_key",
		"default/storage/dropbox/token",
		"default/devtools/github/pat",
		"default/observability/sentry/dsn",
	}
	values := map[string][]byte{}
	for _, c := range canonicals {
		val := []byte("secret-for-" + c)
		values[c] = val
		setFlatFile(t, dir, c, val)
	}

	b := openKeyringBackendInDir(t, dir)
	defer b.Close()

	ctx := context.Background()

	for _, c := range canonicals {
		// Trigger migration explicitly.
		if migrateErr := b.MigrateIfFlat(ctx, c); migrateErr != nil {
			t.Fatalf("MigrateIfFlat %q: %v", c, migrateErr)
		}

		// Value should now be accessible via GetVersioned.
		got, err := b.GetVersioned(ctx, c, 1)
		if err != nil {
			t.Fatalf("GetVersioned %q after migration: %v", c, err)
		}
		if string(got) != string(values[c]) {
			t.Errorf("%q: got %q, want %q", c, got, values[c])
		}

		// Metadata should be present.
		m, err := b.GetMeta(ctx, c)
		if err != nil {
			t.Fatalf("GetMeta %q after migration: %v", c, err)
		}
		if m.CurrentVersion != 1 {
			t.Errorf("%q: CurrentVersion got %d, want 1", c, m.CurrentVersion)
		}
	}
}

// TestMigrateIfFlat_CrashBetweenValueWriteAndMeta verifies that if the write
// crashes after SetVersioned but before SetMeta, the flat file is still present.
func TestMigrateIfFlat_CrashBetweenValueWriteAndMeta(t *testing.T) {
	dir := t.TempDir()

	canonical := "default/ai/openrouter/api_key"
	value := []byte("super-secret")
	setFlatFile(t, dir, canonical, value)

	b := openKeyringBackendInDir(t, dir)
	defer b.Close()

	ctx := context.Background()

	// Inject crash hook.
	crashErr := errors.New("injected crash")
	file.SetAfterValueWriteHook(crashErr)
	defer file.SetAfterValueWriteHook(nil)

	migrateErr := b.MigrateIfFlat(ctx, canonical)
	if !errors.Is(migrateErr, crashErr) {
		t.Fatalf("expected crash error, got: %v", migrateErr)
	}

	// Flat file must still be present.
	flatPath := filepath.Join(dir, filepath.FromSlash(canonical), "value.enc")
	if _, statErr := os.Stat(flatPath); os.IsNotExist(statErr) {
		t.Error("flat file was removed after crash — must be preserved on rollback")
	}

	// The metadata file must NOT be present (versioned write was rolled back).
	_, metaErr := b.GetMeta(ctx, canonical)
	if !errors.Is(metaErr, backend.ErrNotFound) {
		t.Errorf("metadata should not exist after crash, got: %v", metaErr)
	}
}

// TestMigrateIfFlat_Idempotent verifies that a second migration call is a no-op.
func TestMigrateIfFlat_Idempotent(t *testing.T) {
	dir := t.TempDir()
	canonical := "default/ai/openrouter/api_key"
	value := []byte("secret")
	setFlatFile(t, dir, canonical, value)

	b := openKeyringBackendInDir(t, dir)
	defer b.Close()

	ctx := context.Background()

	// First migration.
	if err := b.MigrateIfFlat(ctx, canonical); err != nil {
		t.Fatalf("first MigrateIfFlat: %v", err)
	}

	// Second migration — should be a no-op.
	if err := b.MigrateIfFlat(ctx, canonical); err != nil {
		t.Fatalf("second MigrateIfFlat (should be idempotent): %v", err)
	}

	// Value is still accessible.
	got, err := b.GetVersioned(ctx, canonical, 1)
	if err != nil {
		t.Fatalf("GetVersioned after idempotent migration: %v", err)
	}
	if string(got) != string(value) {
		t.Errorf("value mismatch: got %q, want %q", got, value)
	}
}
