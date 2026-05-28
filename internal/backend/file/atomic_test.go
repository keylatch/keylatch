package file_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend/file"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

// TestAtomicMetadataWrite verifies that concurrent readers never observe
// partial JSON while a writer is in progress.
func TestAtomicMetadataWrite(t *testing.T) {
	dir := t.TempDir()
	b, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	canonical := "default/ai/openrouter/api_key"
	m := validMeta(canonical)

	// Write initial metadata.
	if err := b.SetMeta(context.Background(), canonical, m); err != nil {
		t.Fatalf("initial SetMeta: %v", err)
	}

	metaFile := filepath.Join(dir, "metadata", "default", "ai", "openrouter", "api_key.json")

	stop := make(chan struct{})
	var readErr error
	var mu sync.Mutex

	// Reader goroutine: reads the file in a loop for 200ms, checking for
	// valid JSON on each read.
	go func() {
		deadline := time.Now().Add(200 * time.Millisecond)
		for time.Now().Before(deadline) {
			data, err := os.ReadFile(metaFile)
			if err != nil {
				continue
			}
			var got vmeta.Meta
			if jsonErr := json.Unmarshal(data, &got); jsonErr != nil {
				mu.Lock()
				readErr = fmt.Errorf("partial JSON observed: %w", jsonErr)
				mu.Unlock()
				close(stop)
				return
			}
		}
		close(stop)
	}()

	// Writer: continuously update metadata until the reader stops.
	for {
		select {
		case <-stop:
			goto done
		default:
			m.UpdatedAt = time.Now()
			_ = b.SetMeta(context.Background(), canonical, m)
		}
	}
done:

	mu.Lock()
	defer mu.Unlock()
	if readErr != nil {
		t.Error(readErr)
	}
}

// TestConcurrentWriters verifies that 10 concurrent SetMeta calls produce a
// valid, parseable final result (no JSON corruption).
func TestConcurrentWriters(t *testing.T) {
	dir := t.TempDir()
	b, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	canonical := "default/concurrent/openrouter/api_key"
	const goroutines = 10

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			m := validMeta(canonical)
			m.UpdatedAt = time.Now().Add(time.Duration(n) * time.Millisecond)
			_ = b.SetMeta(context.Background(), canonical, m)
		}(i)
	}
	wg.Wait()

	// Verify the final file is valid JSON.
	got, err := b.GetMeta(context.Background(), canonical)
	if err != nil {
		t.Fatalf("GetMeta after concurrent writes: %v", err)
	}
	if got.Path != canonical {
		t.Errorf("Path mismatch: got %q, want %q", got.Path, canonical)
	}
}

// TestVersionedRoundTrip verifies SetVersioned + GetVersioned returns identical bytes.
// Requires a keyring-backed backend (T-02-03).
func TestVersionedRoundTrip(t *testing.T) {
	b := openKeyringBackend(t)
	defer b.Close()

	canonical := "default/ai/openrouter/api_key"
	want := []byte("encrypted-blob-v1")

	if err := b.SetVersioned(context.Background(), canonical, 1, want); err != nil {
		t.Fatalf("SetVersioned: %v", err)
	}

	got, err := b.GetVersioned(context.Background(), canonical, 1)
	if err != nil {
		t.Fatalf("GetVersioned: %v", err)
	}

	if string(got) != string(want) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, want)
	}
}

// TestDeleteVersionedIdempotent verifies that DeleteVersioned is idempotent.
func TestDeleteVersionedIdempotent(t *testing.T) {
	b := openKeyringBackend(t)
	defer b.Close()

	canonical := "default/ai/openrouter/api_key"

	if err := b.SetVersioned(context.Background(), canonical, 1, []byte("data")); err != nil {
		t.Fatalf("SetVersioned: %v", err)
	}

	if err := b.DeleteVersioned(context.Background(), canonical, 1); err != nil {
		t.Fatalf("DeleteVersioned (first): %v", err)
	}

	// Second call should be a no-op.
	if err := b.DeleteVersioned(context.Background(), canonical, 1); err != nil {
		t.Fatalf("DeleteVersioned (second, should be idempotent): %v", err)
	}
}

// TestVersionedFileModes verifies that value files are written with mode 0o600.
func TestVersionedFileModes(t *testing.T) {
	dir := t.TempDir()
	b := openKeyringBackendInDir(t, dir)
	defer b.Close()

	canonical := "default/ai/openrouter/api_key"
	if err := b.SetVersioned(context.Background(), canonical, 1, []byte("secret")); err != nil {
		t.Fatalf("SetVersioned: %v", err)
	}

	vp := filepath.Join(dir, "values", "default", "ai", "openrouter", "api_key", "1")
	assertPrivateFileMode(t, vp, "value file")
}

// TestMetadataRoundTrip verifies SetMeta + GetMeta returns identical metadata.
func TestMetadataRoundTrip(t *testing.T) {
	dir := t.TempDir()
	b, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	canonical := "default/ai/openrouter/api_key"
	now := time.Now().UTC().Truncate(time.Second)
	m := vmeta.Meta{
		SchemaVersion:  vmeta.CurrentSchemaVersion,
		Path:           canonical,
		Accessor:       vmeta.NewAccessor(),
		Backend:        "file",
		CurrentVersion: 1,
		MaxVersions:    vmeta.DefaultMaxVersions,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := b.SetMeta(context.Background(), canonical, m); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}

	got, err := b.GetMeta(context.Background(), canonical)
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}

	if got.Path != m.Path {
		t.Errorf("Path: got %q, want %q", got.Path, m.Path)
	}
	if got.Accessor != m.Accessor {
		t.Errorf("Accessor mismatch")
	}
	if got.CurrentVersion != m.CurrentVersion {
		t.Errorf("CurrentVersion: got %d, want %d", got.CurrentVersion, m.CurrentVersion)
	}
}

// TestMetadataFileModes verifies that metadata files are written with mode 0o600.
func TestMetadataFileModes(t *testing.T) {
	dir := t.TempDir()
	b, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	canonical := "default/ai/openrouter/api_key"
	m := validMeta(canonical)

	if err := b.SetMeta(context.Background(), canonical, m); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}

	mp := filepath.Join(dir, "metadata", "default", "ai", "openrouter", "api_key.json")
	assertPrivateFileMode(t, mp, "metadata file")
}

// TestListMeta verifies that ListMeta returns sorted metas without reading values.
func TestListMeta(t *testing.T) {
	dir := t.TempDir()
	b, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	paths := []string{
		"default/ai/openrouter/api_key",
		"default/ai/anthropic/api_key",
		"default/storage/dropbox/token",
	}

	for _, p := range paths {
		if err := b.SetMeta(context.Background(), p, validMeta(p)); err != nil {
			t.Fatalf("SetMeta %q: %v", p, err)
		}
	}

	all, err := b.ListMeta(context.Background(), "")
	if err != nil {
		t.Fatalf("ListMeta: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3 metas, got %d", len(all))
	}

	// Should be sorted.
	for i := 1; i < len(all); i++ {
		if all[i-1].Path >= all[i].Path {
			t.Errorf("not sorted: all[%d].Path=%q >= all[%d].Path=%q", i-1, all[i-1].Path, i, all[i].Path)
		}
	}

	// Prefix filter.
	aiMetas, err := b.ListMeta(context.Background(), "default/ai")
	if err != nil {
		t.Fatalf("ListMeta with prefix: %v", err)
	}
	if len(aiMetas) != 2 {
		t.Errorf("expected 2 ai metas, got %d", len(aiMetas))
	}
}

// validMeta returns a minimal valid vmeta.Meta for a given canonical path.
func validMeta(canonical string) vmeta.Meta {
	now := time.Now().UTC().Truncate(time.Second)
	return vmeta.Meta{
		SchemaVersion:  vmeta.CurrentSchemaVersion,
		Path:           canonical,
		Accessor:       vmeta.NewAccessor(),
		Backend:        "file",
		CurrentVersion: 1,
		MaxVersions:    vmeta.DefaultMaxVersions,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}
