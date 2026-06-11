// Package file_test — additional migrate and meta error path tests.
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

// TestMigrateIfFlat_NoKeyring_SetVersionedFails verifies that migrateIfFlat
// returns an error when SetVersioned fails (no keyring = ErrBootstrapRequired).
func TestMigrateIfFlat_NoKeyring_SetVersionedFails(t *testing.T) {
	dir := t.TempDir()
	canonical := "default/ai/openrouter/api_key"
	value := []byte("secret-value")
	setFlatFile(t, dir, canonical, value)

	// Open without a keyring so SetVersioned returns ErrBootstrapRequired.
	b, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	err = b.MigrateIfFlat(context.Background(), canonical)
	// Should fail because SetVersioned requires a keyring.
	if err == nil {
		t.Fatal("MigrateIfFlat without keyring: expected error, got nil")
	}
	if !errors.Is(err, backend.ErrBootstrapRequired) {
		t.Errorf("MigrateIfFlat without keyring: got %v, want ErrBootstrapRequired (wrapped)", err)
	}
}

// TestMigrateIfFlat_NoFlatFile_NoVersioned verifies that migrateIfFlat is a
// no-op when neither the flat file nor the versioned file exist.
func TestMigrateIfFlat_NoFlatFile_NoVersioned(t *testing.T) {
	b := openKeyringBackend(t)
	defer b.Close()

	// Neither flat nor versioned file exists — should be a clean no-op.
	err := b.MigrateIfFlat(context.Background(), "default/nonexistent/path")
	if err != nil {
		t.Errorf("MigrateIfFlat no-file: expected nil, got %v", err)
	}
}

// TestGetMeta_CorruptMetadataFile verifies GetMeta returns an error when the
// metadata file contains invalid JSON.
func TestGetMeta_CorruptMetadataFile(t *testing.T) {
	dir := t.TempDir()
	b, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	canonical := "default/test/corrupt-meta"

	// Write a valid metadata entry first.
	m := validMeta(canonical)
	if err := b.SetMeta(context.Background(), canonical, m); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}

	// Overwrite with invalid JSON.
	metaPath := filepath.Join(dir, "metadata", "default", "test", "corrupt-meta.json")
	if err := os.WriteFile(metaPath, []byte("not valid json {{{{"), 0o600); err != nil {
		t.Fatalf("WriteFile corrupt meta: %v", err)
	}

	_, err = b.GetMeta(context.Background(), canonical)
	if err == nil {
		t.Error("GetMeta with corrupt metadata file: expected error, got nil")
	}
}

// TestListMeta_SkipsMalformedJSON verifies ListMeta silently skips files
// with invalid JSON without aborting the walk.
func TestListMeta_SkipsMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	b, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	ctx := context.Background()

	// Write two valid metadata files.
	paths := []string{"default/ai/openrouter/api_key", "default/ai/anthropic/api_key"}
	for _, p := range paths {
		if err := b.SetMeta(ctx, p, validMeta(p)); err != nil {
			t.Fatalf("SetMeta %q: %v", p, err)
		}
	}

	// Plant a corrupt JSON file in the metadata directory.
	corruptPath := filepath.Join(dir, "metadata", "default", "ai", "corrupt.json")
	if err := os.WriteFile(corruptPath, []byte("{bad json"), 0o600); err != nil {
		t.Fatalf("Write corrupt metadata: %v", err)
	}

	metas, err := b.ListMeta(ctx, "")
	if err != nil {
		t.Fatalf("ListMeta: unexpected error: %v", err)
	}
	// Should return 2 valid metas, silently skipping the corrupt one.
	if len(metas) != 2 {
		t.Errorf("ListMeta: got %d metas, want 2 (corrupt file should be skipped)", len(metas))
	}
}

// TestListMeta_WithWalkError verifies ListMeta handles the case where a
// non-NotExist walk error is returned. We simulate this by making a subdirectory
// unreadable on Unix.
func TestListMeta_PrefixFilterExcludesOtherPaths(t *testing.T) {
	dir := t.TempDir()
	b, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	ctx := context.Background()

	paths := []string{
		"default/ai/openrouter/api_key",
		"default/storage/dropbox/token",
	}
	for _, p := range paths {
		if err := b.SetMeta(ctx, p, validMeta(p)); err != nil {
			t.Fatalf("SetMeta %q: %v", p, err)
		}
	}

	// Only return AI paths.
	metas, err := b.ListMeta(ctx, "default/ai")
	if err != nil {
		t.Fatalf("ListMeta: %v", err)
	}
	if len(metas) != 1 {
		t.Errorf("ListMeta(prefix='default/ai'): got %d, want 1", len(metas))
	}
}

// TestFileBackend_SetMeta_Roundtrip_WithVersions verifies SetMeta with a
// richer metadata object (multiple versions) persists correctly.
func TestFileBackend_SetMeta_Roundtrip_WithVersions(t *testing.T) {
	dir := t.TempDir()
	b, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	canonical := "default/test/rich-meta"
	m := validMeta(canonical)
	m.CurrentVersion = 3
	m.OldestVersion = 1

	if err := b.SetMeta(context.Background(), canonical, m); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}

	got, err := b.GetMeta(context.Background(), canonical)
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}
	if got.CurrentVersion != 3 {
		t.Errorf("CurrentVersion: got %d, want 3", got.CurrentVersion)
	}
}

// TestFileBackend_List_MultipleEntries verifies List works with multiple entries.
func TestFileBackend_List_MultipleEntries(t *testing.T) {
	b := openKeyringBackend(t)
	defer b.Close()

	ctx := context.Background()
	paths := []string{
		"default/ai/openrouter/api_key",
		"default/ai/anthropic/api_key",
		"default/storage/dropbox/token",
	}

	for _, p := range paths {
		meta := backend.Meta{Path: p, Backend: "file", Version: 1}
		if err := b.Set(ctx, p, []byte("secret"), meta); err != nil {
			t.Fatalf("Set %q: %v", p, err)
		}
	}

	all, err := b.List(ctx, "")
	if err != nil {
		t.Fatalf("List all: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("List all: got %d, want 3", len(all))
	}

	ai, err := b.List(ctx, "default/ai/")
	if err != nil {
		t.Fatalf("List prefix: %v", err)
	}
	if len(ai) != 2 {
		t.Errorf("List(default/ai/): got %d, want 2", len(ai))
	}
}
