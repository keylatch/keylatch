package file_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/file"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
)

func vaultFiles(dir, path string) []string {
	base := filepath.Join(dir, filepath.FromSlash(path), "value.enc")
	return []string{base, base + ".nonce", base + ".aad"}
}

func swapFiles(t *testing.T, a, b []string) {
	t.Helper()
	for i := range a {
		da, err := os.ReadFile(a[i])
		if err != nil {
			t.Fatal(err)
		}
		db, err := os.ReadFile(b[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(a[i], db, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(b[i], da, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// Two secrets whose files are swapped must not decrypt under each other's
// path: the AEAD tag only proves the binding is unchanged, so the stored
// binding is compared with what was asked for.
func TestAADPathMismatchRejected(t *testing.T) {
	root := t.TempDir()
	kr, _ := buildKeyring(t, root, envelope.XChaCha20Poly1305)
	dir := filepath.Join(root, "vault")
	fb, err := file.OpenWithKeyring(file.Options{Dir: dir}, kr)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const a, b = "default/ai/alpha/api_key", "default/ai/beta/api_key"
	for path, v := range map[string]string{a: "alpha-value", b: "beta-value"} {
		if err := fb.Set(ctx, path, []byte(v), backend.Meta{}); err != nil {
			t.Fatal(err)
		}
	}

	swapFiles(t, vaultFiles(dir, a), vaultFiles(dir, b))

	for _, path := range []string{a, b} {
		if v, _, err := fb.Get(ctx, path); err == nil || !errors.Is(err, file.ErrAADMismatch) {
			t.Errorf("Get(%q) = %q, %v; want ErrAADMismatch", path, v, err)
		}
	}
}

// The partition and the version in the stored binding are compared too.
func TestAADPartitionAndVersionMismatchRejected(t *testing.T) {
	root := t.TempDir()
	kr, _ := buildKeyring(t, root, envelope.XChaCha20Poly1305)
	dir := filepath.Join(root, "vault")
	fb, err := file.OpenWithKeyring(file.Options{Dir: dir}, kr)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const path = "default/ai/alpha/api_key"
	if err := fb.Set(ctx, path, []byte("alpha-value"), backend.Meta{}); err != nil {
		t.Fatal(err)
	}
	aadPath := vaultFiles(dir, path)[2]
	original, err := os.ReadFile(aadPath)
	if err != nil {
		t.Fatal(err)
	}

	for field, value := range map[string]any{"namespace": "other", "version": 7} {
		var binding map[string]any
		if err := json.Unmarshal(original, &binding); err != nil {
			t.Fatal(err)
		}
		binding[field] = value
		edited, _ := json.Marshal(binding)
		if err := os.WriteFile(aadPath, edited, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := fb.Get(ctx, path); !errors.Is(err, file.ErrAADMismatch) {
			t.Errorf("a binding with a different %s: err = %v, want ErrAADMismatch", field, err)
		}
	}

	if err := os.WriteFile(aadPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if v, _, err := fb.Get(ctx, path); err != nil || string(v) != "alpha-value" {
		t.Fatalf("an untouched binding must still read: %q, %v", v, err)
	}
}

// Backends on one vault directory stand in for separate processes: each opens
// its own lock handle, and the lock serializes handles. No write may be lost
// to another backend saving a manifest it loaded earlier.
func TestFileBackendCrossProcessLock(t *testing.T) {
	root := t.TempDir()
	kr, _ := buildKeyring(t, root, envelope.XChaCha20Poly1305)
	dir := filepath.Join(root, "vault")

	const writers, perWriter = 4, 15
	backends := make([]*file.FileBackend, writers)
	for i := range backends {
		fb, err := file.OpenWithKeyring(file.Options{Dir: dir}, kr)
		if err != nil {
			t.Fatal(err)
		}
		backends[i] = fb
	}

	var wg sync.WaitGroup
	errs := make(chan error, writers*perWriter)
	for w, fb := range backends {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range perWriter {
				path := fmt.Sprintf("default/ai/w%d-n%d/api_key", w, n)
				if err := fb.Set(context.Background(), path, []byte(path), backend.Meta{}); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	fresh, err := file.OpenWithKeyring(file.Options{Dir: dir}, kr)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := fresh.List(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != writers*perWriter {
		t.Fatalf("manifest holds %d entries, want %d: updates were lost", len(entries), writers*perWriter)
	}
	for _, e := range entries {
		v, _, err := fresh.Get(context.Background(), e.Path)
		if err != nil || string(v) != e.Path {
			t.Errorf("Get(%q) = %q, %v", e.Path, v, err)
		}
	}
}

func TestFileBackendDeleteSeesAnotherWritersEntries(t *testing.T) {
	root := t.TempDir()
	kr, _ := buildKeyring(t, root, envelope.XChaCha20Poly1305)
	dir := filepath.Join(root, "vault")
	a, _ := file.OpenWithKeyring(file.Options{Dir: dir}, kr)
	b, _ := file.OpenWithKeyring(file.Options{Dir: dir}, kr)
	ctx := context.Background()

	if err := a.Set(ctx, "default/ai/one/api_key", []byte("1"), backend.Meta{}); err != nil {
		t.Fatal(err)
	}
	if err := b.Set(ctx, "default/ai/two/api_key", []byte("2"), backend.Meta{}); err != nil {
		t.Fatal(err)
	}
	if err := a.Delete(ctx, "default/ai/one/api_key"); err != nil {
		t.Fatal(err)
	}
	fresh, err := file.OpenWithKeyring(file.Options{Dir: dir}, kr)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := fresh.List(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Path != "default/ai/two/api_key" {
		t.Fatalf("entries = %v; the delete dropped the other writer's secret", entries)
	}
}
