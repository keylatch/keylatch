// Package memory_test contains unit tests for the in-memory backend.
package memory_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/memory"
	"github.com/keylatch/keylatch/internal/backendtest"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

// TestMemory_ComplianceHarness runs the standard backend compliance suite.
func TestMemory_ComplianceHarness(t *testing.T) {
	backendtest.RunBackendComplianceTests(t, func() backend.Backend {
		return memory.New()
	})
}

// TestMemory_Name verifies Name() returns "memory".
func TestMemory_Name(t *testing.T) {
	b := memory.New()
	if b.Name() != "memory" {
		t.Errorf("Name() = %q, want %q", b.Name(), "memory")
	}
}

// TestMemory_ID verifies ID() returns a non-empty stable string.
func TestMemory_ID(t *testing.T) {
	b := memory.New()
	if b.ID() == "" {
		t.Error("ID() returned empty string")
	}
}

// TestMemory_Capabilities verifies CapList is advertised.
func TestMemory_Capabilities(t *testing.T) {
	b := memory.New()
	caps := b.Capabilities()
	found := false
	for _, c := range caps {
		if c == backend.CapList {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Capabilities() = %v, want CapList to be present", caps)
	}
}

// TestMemory_GetNotFound verifies Get on a missing key returns ErrNotFound.
func TestMemory_GetNotFound(t *testing.T) {
	b := memory.New()
	_, _, err := b.Get(context.Background(), "does/not/exist")
	if !errors.Is(err, backend.ErrNotFound) {
		t.Errorf("Get missing key: got %v, want ErrNotFound", err)
	}
}

// TestMemory_SetGet verifies a basic Set → Get round-trip.
func TestMemory_SetGet(t *testing.T) {
	b := memory.New()
	ctx := context.Background()
	path := "default/ai/openrouter/api_key"
	want := []byte("sk-test-1234")

	if err := b.Set(ctx, path, want, backend.Meta{}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, meta, err := b.Get(ctx, path)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("Get value: got %q, want %q", got, want)
	}
	if meta.Path != path {
		t.Errorf("Get meta.Path: got %q, want %q", meta.Path, path)
	}
	if meta.Backend != "memory" {
		t.Errorf("Get meta.Backend: got %q, want %q", meta.Backend, "memory")
	}
}

// TestMemory_SetIsolated verifies that Set stores a copy — mutating the
// input slice after Set does not affect the stored value.
func TestMemory_SetIsolated(t *testing.T) {
	b := memory.New()
	ctx := context.Background()
	path := "default/test/isolation"
	original := []byte("value")
	input := make([]byte, len(original))
	copy(input, original)

	if err := b.Set(ctx, path, input, backend.Meta{}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Mutate the input after storing.
	for i := range input {
		input[i] = 0xFF
	}

	got, _, err := b.Get(ctx, path)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(original) {
		t.Errorf("isolation: got %q, want %q", got, original)
	}
}

// TestMemory_GetIsolated verifies that the caller mutating the returned
// slice does not corrupt the stored value.
func TestMemory_GetIsolated(t *testing.T) {
	b := memory.New()
	ctx := context.Background()
	path := "default/test/get-isolation"
	want := []byte("stable-value")

	if err := b.Set(ctx, path, want, backend.Meta{}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, _, err := b.Get(ctx, path)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Mutate the returned slice.
	for i := range got {
		got[i] = 0xFF
	}

	// Second Get should return the original value.
	got2, _, err := b.Get(ctx, path)
	if err != nil {
		t.Fatalf("Get2: %v", err)
	}
	if string(got2) != string(want) {
		t.Errorf("get isolation: got %q, want %q", got2, want)
	}
}

// TestMemory_Delete verifies Delete removes the key and makes it unfindable.
func TestMemory_Delete(t *testing.T) {
	b := memory.New()
	ctx := context.Background()
	path := "default/test/delete-me"

	if err := b.Set(ctx, path, []byte("val"), backend.Meta{}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := b.Delete(ctx, path); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, _, err := b.Get(ctx, path)
	if !errors.Is(err, backend.ErrNotFound) {
		t.Errorf("Get after Delete: got %v, want ErrNotFound", err)
	}
}

// TestMemory_DeleteIdempotent verifies that deleting a missing key is not
// an error (idempotent contract).
func TestMemory_DeleteIdempotent(t *testing.T) {
	b := memory.New()
	ctx := context.Background()
	if err := b.Delete(ctx, "does/not/exist"); err != nil {
		t.Errorf("Delete missing key: got %v, want nil", err)
	}
}

// TestMemory_List_Empty verifies List returns an empty slice when no keys match.
func TestMemory_List_Empty(t *testing.T) {
	b := memory.New()
	entries, err := b.List(context.Background(), "no/match/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("List empty prefix: got %d entries, want 0", len(entries))
	}
}

// TestMemory_List_PrefixMatch verifies List returns all entries matching
// the given prefix.
func TestMemory_List_PrefixMatch(t *testing.T) {
	b := memory.New()
	ctx := context.Background()

	paths := []string{
		"default/ai/openrouter/api_key",
		"default/ai/anthropic/api_key",
		"default/storage/dropbox/token",
	}
	for _, p := range paths {
		if err := b.Set(ctx, p, []byte("v"), backend.Meta{}); err != nil {
			t.Fatalf("Set %q: %v", p, err)
		}
	}

	entries, err := b.List(ctx, "default/ai/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("List prefix=default/ai/: got %d entries, want 2", len(entries))
	}

	for _, e := range entries {
		if !e.Exists {
			t.Errorf("entry %q: Exists should be true", e.Path)
		}
		if e.Backend != "memory" {
			t.Errorf("entry %q: Backend=%q, want %q", e.Path, e.Backend, "memory")
		}
	}
}

// TestMemory_List_EmptyPrefix verifies List("") returns all entries.
func TestMemory_List_EmptyPrefix(t *testing.T) {
	b := memory.New()
	ctx := context.Background()

	for _, p := range []string{"a/b/c", "x/y/z", "foo/bar"} {
		if err := b.Set(ctx, p, []byte("v"), backend.Meta{}); err != nil {
			t.Fatalf("Set: %v", err)
		}
	}

	entries, err := b.List(ctx, "")
	if err != nil {
		t.Fatalf("List empty prefix: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("List(\"\") got %d entries, want 3", len(entries))
	}
}

// TestMemory_GetMeta_NotSupported verifies GetMeta returns ErrNotSupported.
func TestMemory_GetMeta_NotSupported(t *testing.T) {
	b := memory.New()
	_, err := b.GetMeta(context.Background(), "any/path")
	if !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("GetMeta: got %v, want ErrNotSupported", err)
	}
}

// TestMemory_SetMeta_NotSupported verifies SetMeta returns ErrNotSupported.
func TestMemory_SetMeta_NotSupported(t *testing.T) {
	b := memory.New()
	err := b.SetMeta(context.Background(), "any/path", vmeta.Meta{})
	if !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("SetMeta: got %v, want ErrNotSupported", err)
	}
}

// TestMemory_ListMeta_NotSupported verifies ListMeta returns ErrNotSupported.
func TestMemory_ListMeta_NotSupported(t *testing.T) {
	b := memory.New()
	_, err := b.ListMeta(context.Background(), "")
	if !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("ListMeta: got %v, want ErrNotSupported", err)
	}
}

// TestMemory_GetVersioned_NotSupported verifies GetVersioned returns ErrNotSupported.
func TestMemory_GetVersioned_NotSupported(t *testing.T) {
	b := memory.New()
	_, err := b.GetVersioned(context.Background(), "any/path", 1)
	if !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("GetVersioned: got %v, want ErrNotSupported", err)
	}
}

// TestMemory_SetVersioned_NotSupported verifies SetVersioned returns ErrNotSupported.
func TestMemory_SetVersioned_NotSupported(t *testing.T) {
	b := memory.New()
	err := b.SetVersioned(context.Background(), "any/path", 1, []byte("v"))
	if !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("SetVersioned: got %v, want ErrNotSupported", err)
	}
}

// TestMemory_DeleteVersioned_NotSupported verifies DeleteVersioned returns ErrNotSupported.
func TestMemory_DeleteVersioned_NotSupported(t *testing.T) {
	b := memory.New()
	err := b.DeleteVersioned(context.Background(), "any/path", 1)
	if !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("DeleteVersioned: got %v, want ErrNotSupported", err)
	}
}

// TestMemory_Close verifies Close is a no-op returning nil.
func TestMemory_Close(t *testing.T) {
	b := memory.New()
	if err := b.Close(); err != nil {
		t.Errorf("Close: got %v, want nil", err)
	}
	// Idempotent — call again.
	if err := b.Close(); err != nil {
		t.Errorf("Close (second): got %v, want nil", err)
	}
}

// TestMemory_ConcurrentSetGet exercises the mutex under concurrent reads/writes.
func TestMemory_ConcurrentSetGet(t *testing.T) {
	b := memory.New()
	ctx := context.Background()
	const workers = 20

	var wg sync.WaitGroup
	wg.Add(workers * 2)

	for i := 0; i < workers; i++ {
		path := "default/concurrent/" + string(rune('a'+i))
		go func(p string) {
			defer wg.Done()
			_ = b.Set(ctx, p, []byte("value"), backend.Meta{})
		}(path)
		go func(p string) {
			defer wg.Done()
			_, _, _ = b.Get(ctx, p)
		}(path)
	}
	wg.Wait()
}

// TestMemory_Overwrite verifies that setting the same path twice overwrites
// the previous value.
func TestMemory_Overwrite(t *testing.T) {
	b := memory.New()
	ctx := context.Background()
	path := "default/test/overwrite"

	if err := b.Set(ctx, path, []byte("first"), backend.Meta{}); err != nil {
		t.Fatalf("Set first: %v", err)
	}
	if err := b.Set(ctx, path, []byte("second"), backend.Meta{}); err != nil {
		t.Fatalf("Set second: %v", err)
	}

	got, _, err := b.Get(ctx, path)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "second" {
		t.Errorf("overwrite: got %q, want %q", got, "second")
	}
}
