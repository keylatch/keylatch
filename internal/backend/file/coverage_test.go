// Package file_test — additional coverage tests targeting previously
// uncovered code paths: Capabilities, ActiveKeyTerm, Open errors,
// List/Delete error paths, readVersionMeta missing/corrupt, and manifest
// corrupt load.
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

// TestFileBackend_Capabilities verifies Capabilities returns the expected set.
func TestFileBackend_Capabilities(t *testing.T) {
	b, err := file.Open(file.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	caps := b.Capabilities()
	capSet := make(map[backend.Capability]bool, len(caps))
	for _, c := range caps {
		capSet[c] = true
	}

	required := []backend.Capability{
		backend.CapList,
		backend.CapMetadata,
		backend.CapImport,
		backend.CapExport,
	}
	for _, c := range required {
		if !capSet[c] {
			t.Errorf("Capabilities() missing %v", c)
		}
	}
}

// TestFileBackend_ActiveKeyTerm_NoKeyring verifies ActiveKeyTerm returns 0
// when no keyring is configured.
func TestFileBackend_ActiveKeyTerm_NoKeyring(t *testing.T) {
	b, err := file.Open(file.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	term, err := b.ActiveKeyTerm()
	if err != nil {
		t.Fatalf("ActiveKeyTerm: %v", err)
	}
	if term != 0 {
		t.Errorf("ActiveKeyTerm without keyring: got %d, want 0", term)
	}
}

// TestFileBackend_ActiveKeyTerm_WithKeyring verifies ActiveKeyTerm returns
// a positive term number when a keyring is present.
func TestFileBackend_ActiveKeyTerm_WithKeyring(t *testing.T) {
	b := openKeyringBackend(t)
	defer b.Close()

	term, err := b.ActiveKeyTerm()
	if err != nil {
		t.Fatalf("ActiveKeyTerm with keyring: %v", err)
	}
	if term <= 0 {
		t.Errorf("ActiveKeyTerm with keyring: got %d, want > 0", term)
	}
}

// TestFileBackend_Open_EmptyDir verifies Open returns an error when Dir is empty.
func TestFileBackend_Open_EmptyDir(t *testing.T) {
	_, err := file.Open(file.Options{Dir: ""})
	if err == nil {
		t.Error("Open with empty Dir: expected error, got nil")
	}
}

// TestFileBackend_Delete_NotFound verifies Delete returns ErrNotFound for
// a path not in the manifest.
func TestFileBackend_Delete_NotFound(t *testing.T) {
	b := openKeyringBackend(t)
	defer b.Close()

	err := b.Delete(context.Background(), "does/not/exist")
	if !errors.Is(err, backend.ErrNotFound) {
		t.Errorf("Delete missing path: got %v, want ErrNotFound", err)
	}
}

// TestFileBackend_GetVersioned_NoKeyring verifies GetVersioned without a
// keyring returns ErrBootstrapRequired.
func TestFileBackend_GetVersioned_NoKeyring(t *testing.T) {
	b, err := file.Open(file.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	_, err = b.GetVersioned(context.Background(), "any/path", 1)
	if !errors.Is(err, backend.ErrBootstrapRequired) {
		t.Errorf("GetVersioned without keyring: got %v, want ErrBootstrapRequired", err)
	}
}

// TestFileBackend_SetVersioned_NoKeyring verifies SetVersioned without a
// keyring returns ErrBootstrapRequired.
func TestFileBackend_SetVersioned_NoKeyring(t *testing.T) {
	b, err := file.Open(file.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	err = b.SetVersioned(context.Background(), "any/path", 1, []byte("val"))
	if !errors.Is(err, backend.ErrBootstrapRequired) {
		t.Errorf("SetVersioned without keyring: got %v, want ErrBootstrapRequired", err)
	}
}

// TestFileBackend_GetVersioned_MissingSidecar verifies GetVersioned returns
// an error when the version sidecar (.versionmeta) is absent.
func TestFileBackend_GetVersioned_MissingSidecar(t *testing.T) {
	b := openKeyringBackend(t)
	defer b.Close()

	// There is no sidecar for this path/version.
	_, err := b.GetVersioned(context.Background(), "default/never/written", 1)
	// Should be ErrNotFound (from readVersionMeta).
	if !errors.Is(err, backend.ErrNotFound) {
		t.Errorf("GetVersioned missing sidecar: got %v, want ErrNotFound (or wrapped)", err)
	}
}

// TestFileBackend_GetVersioned_CorruptSidecar verifies GetVersioned returns
// an error when the version sidecar contains invalid JSON.
func TestFileBackend_GetVersioned_CorruptSidecar(t *testing.T) {
	dir := t.TempDir()
	b := openKeyringBackendInDir(t, dir)
	defer b.Close()

	// Write a valid version first.
	canonical := "default/test/corrupt-sidecar"
	if err := b.SetVersioned(context.Background(), canonical, 1, []byte("secret")); err != nil {
		t.Fatalf("SetVersioned: %v", err)
	}

	// Overwrite the sidecar with garbage JSON.
	sidecarPath := filepath.Join(dir, "values", "default", "test", "corrupt-sidecar", "1.versionmeta")
	if err := os.WriteFile(sidecarPath, []byte("not valid json {{{{"), 0o600); err != nil {
		t.Fatalf("corrupt sidecar: %v", err)
	}

	_, err := b.GetVersioned(context.Background(), canonical, 1)
	if err == nil {
		t.Error("GetVersioned with corrupt sidecar: expected error, got nil")
	}
}

// TestFileBackend_GetMeta_NotFound verifies GetMeta returns ErrNotFound when
// no metadata file exists for the given path.
func TestFileBackend_GetMeta_NotFound(t *testing.T) {
	b, err := file.Open(file.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	_, err = b.GetMeta(context.Background(), "does/not/exist")
	if !errors.Is(err, backend.ErrNotFound) {
		t.Errorf("GetMeta missing path: got %v, want ErrNotFound", err)
	}
}

// TestFileBackend_List_EmptyManifest verifies List returns an empty slice when
// no secrets have been written.
func TestFileBackend_List_EmptyManifest(t *testing.T) {
	b, err := file.Open(file.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	entries, err := b.List(context.Background(), "default/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("List empty backend: got %d entries, want 0", len(entries))
	}
}

// TestFileBackend_List_EmptyPrefix verifies List("") returns all entries.
func TestFileBackend_List_EmptyPrefix(t *testing.T) {
	b := openKeyringBackend(t)
	defer b.Close()

	paths := []string{"default/a/key", "default/b/key"}
	for _, p := range paths {
		meta := backend.Meta{Path: p, Backend: "file", Version: 1}
		if err := b.Set(context.Background(), p, []byte("val"), meta); err != nil {
			t.Fatalf("Set %q: %v", p, err)
		}
	}

	entries, err := b.List(context.Background(), "")
	if err != nil {
		t.Fatalf("List with empty prefix: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("List(\"\") got %d entries, want 2", len(entries))
	}
}

// TestFileBackend_ManifestCorrupt verifies that a corrupt manifest.json
// causes an error on the first operation.
func TestFileBackend_ManifestCorrupt(t *testing.T) {
	dir := t.TempDir()

	// Write an invalid manifest.
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte("not valid json {{{{"), 0o600); err != nil {
		t.Fatalf("write corrupt manifest: %v", err)
	}

	b, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	// Any operation that loads the manifest should return an error.
	_, err = b.List(context.Background(), "")
	if err == nil {
		t.Error("List with corrupt manifest: expected error, got nil")
	}
}

// TestFileBackend_SetMeta_EnsuresDirCreated verifies that SetMeta creates
// intermediate directories automatically.
func TestFileBackend_SetMeta_EnsuresDirCreated(t *testing.T) {
	dir := t.TempDir()
	b, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	canonical := "default/deep/nested/path/key"
	m := validMeta(canonical)
	if err := b.SetMeta(context.Background(), canonical, m); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}

	// Verify the metadata file was created.
	got, err := b.GetMeta(context.Background(), canonical)
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}
	if got.Path != canonical {
		t.Errorf("SetMeta/GetMeta: Path = %q, want %q", got.Path, canonical)
	}
}

// TestFileBackend_ID verifies that ID returns a non-empty string prefixed with "file:".
func TestFileBackend_ID(t *testing.T) {
	dir := t.TempDir()
	b, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	id := b.ID()
	if id == "" {
		t.Error("ID() returned empty string")
	}
	prefix := "file:"
	if len(id) < len(prefix) || id[:len(prefix)] != prefix {
		t.Errorf("ID() = %q; want prefix %q", id, prefix)
	}
}

// TestFileBackend_ListMeta_EmptyDir verifies ListMeta returns an empty slice
// when no metadata files exist.
func TestFileBackend_ListMeta_EmptyDir(t *testing.T) {
	b, err := file.Open(file.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	metas, err := b.ListMeta(context.Background(), "")
	if err != nil {
		t.Fatalf("ListMeta on empty dir: %v", err)
	}
	if len(metas) != 0 {
		t.Errorf("ListMeta on empty dir: got %d entries, want 0", len(metas))
	}
}

// TestFileBackend_DeleteVersioned_Existing verifies that DeleteVersioned
// removes an existing version file.
func TestFileBackend_DeleteVersioned_Existing(t *testing.T) {
	b := openKeyringBackend(t)
	defer b.Close()

	canonical := "default/test/delete-versioned"
	if err := b.SetVersioned(context.Background(), canonical, 1, []byte("data")); err != nil {
		t.Fatalf("SetVersioned: %v", err)
	}

	if err := b.DeleteVersioned(context.Background(), canonical, 1); err != nil {
		t.Fatalf("DeleteVersioned: %v", err)
	}

	// Second call should also succeed (idempotent).
	if err := b.DeleteVersioned(context.Background(), canonical, 1); err != nil {
		t.Fatalf("DeleteVersioned idempotent: %v", err)
	}
}

// TestFileBackend_WriteVersionMeta_RoundTrip verifies that SetVersioned
// writes a sidecar and GetVersioned can decrypt it.
func TestFileBackend_WriteVersionMeta_RoundTrip(t *testing.T) {
	b := openKeyringBackend(t)
	defer b.Close()

	canonical := "default/test/version-meta-roundtrip"
	want := []byte("version-meta-test-value")

	if err := b.SetVersioned(context.Background(), canonical, 2, want); err != nil {
		t.Fatalf("SetVersioned v2: %v", err)
	}

	got, err := b.GetVersioned(context.Background(), canonical, 2)
	if err != nil {
		t.Fatalf("GetVersioned v2: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("v2 round-trip: got %q, want %q", got, want)
	}
}
