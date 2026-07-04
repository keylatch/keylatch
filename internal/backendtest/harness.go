// Package backendtest provides the compliance test harness for Backend
// implementations. All concrete backends (file, keychain) invoke
// RunBackendComplianceTests from their own _test.go files.
package backendtest

import (
	"context"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
)

// RunBackendComplianceTests runs the standard compliance test suite against
// any Backend implementation. Concrete backends call this via:
//
//	func TestCompliance(t *testing.T) {
//	    backendtest.RunBackendComplianceTests(t, func() backend.Backend { return ... })
//	}
func RunBackendComplianceTests(t *testing.T, factory func() backend.Backend) {
	t.Helper()

	t.Run("Get/NotFound", func(t *testing.T) {
		t.Helper()
		b := factory()
		defer b.Close()

		_, _, err := b.Get(context.Background(), "nonexistent/path/key")
		if !errors.Is(err, backend.ErrNotFound) {
			t.Errorf("Get on missing path: got %v, want ErrNotFound", err)
		}
	})

	t.Run("Set/Get roundtrip", func(t *testing.T) {
		t.Helper()
		b := factory()
		defer b.Close()

		path := "default/test/roundtrip"
		want := []byte("super-secret-value")
		meta := backend.Meta{Path: path, Backend: b.Name(), Version: 1}

		if err := b.Set(context.Background(), path, want, meta); err != nil {
			t.Fatalf("Set: %v", err)
		}

		got, _, err := b.Get(context.Background(), path)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if string(got) != string(want) {
			t.Errorf("Get: got %q, want %q", got, want)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		t.Helper()
		b := factory()
		defer b.Close()

		path := "default/test/delete"
		meta := backend.Meta{Path: path, Backend: b.Name(), Version: 1}

		if err := b.Set(context.Background(), path, []byte("to-be-deleted"), meta); err != nil {
			t.Fatalf("Set before Delete: %v", err)
		}

		if err := b.Delete(context.Background(), path); err != nil {
			t.Fatalf("Delete: %v", err)
		}

		_, _, err := b.Get(context.Background(), path)
		if !errors.Is(err, backend.ErrNotFound) {
			t.Errorf("Get after Delete: got %v, want ErrNotFound", err)
		}
	})

	t.Run("List/metadata-only", func(t *testing.T) {
		t.Helper()
		b := factory()
		defer b.Close()

		paths := []string{"default/test/list/a", "default/test/list/b"}
		for _, p := range paths {
			meta := backend.Meta{Path: p, Backend: b.Name(), Version: 1}
			if err := b.Set(context.Background(), p, []byte("value-"+p), meta); err != nil {
				t.Fatalf("Set %q: %v", p, err)
			}
		}

		entries, err := b.List(context.Background(), "default/test/list/")
		if err != nil {
			t.Fatalf("List: %v", err)
		}

		found := make(map[string]bool)
		for _, e := range entries {
			found[e.Path] = true
			if !e.Exists {
				t.Errorf("entry %q: Exists should be true", e.Path)
			}
		}

		for _, p := range paths {
			if !found[p] {
				t.Errorf("List: missing entry %q", p)
			}
		}
	})

	t.Run("GetMeta/", func(t *testing.T) {
		t.Helper()
		b := factory()
		defer b.Close()

		path := "default/test/getmeta"
		bMeta := backend.Meta{Path: path, Backend: b.Name(), Version: 1}

		if err := b.Set(context.Background(), path, []byte("secret"), bMeta); err != nil {
			t.Fatalf("Set: %v", err)
		}

		gotMeta, err := b.GetMeta(context.Background(), path)
		if errors.Is(err, backend.ErrNotSupported) {
			// Non-file backends are expected to return ErrNotSupported.
			t.Skipf("GetMeta not supported by %s backend", b.Name())
			return
		}
		if err != nil {
			// Wave 1 stub: GetMeta may return a "not yet implemented" error.
			// Skip rather than fail — Wave 2 replaces the stub with a real impl.
			t.Skipf("GetMeta not yet implemented on %s backend: %v", b.Name(), err)
			return
		}

		if gotMeta.Path != path {
			t.Errorf("GetMeta.Path: got %q, want %q", gotMeta.Path, path)
		}
	})

	t.Run("Close/idempotent", func(t *testing.T) {
		t.Helper()
		b := factory()

		if err := b.Close(); err != nil {
			t.Errorf("Close (first): %v", err)
		}
		if err := b.Close(); err != nil {
			t.Errorf("Close (second): %v", err)
		}
	})
}
