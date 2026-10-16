package brokerstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/brokerd/keys"
)

// vaultReader is the read interface the gateway takes; Store satisfies it.
type vaultReader interface {
	Get(ctx context.Context, path string) ([]byte, backend.Meta, error)
}

var _ vaultReader = (*Store)(nil)

func newKeys(t *testing.T) *keys.Hierarchy {
	t.Helper()
	h, err := keys.Open(t.TempDir(), bytes.Repeat([]byte{7}, 40), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return h
}

func newStore(t *testing.T, h *keys.Hierarchy, dir, partition string) *Store {
	t.Helper()
	s, err := Open(dir, partition, h)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func putAll(t *testing.T, s *Store, items map[string]string) {
	t.Helper()
	for p, v := range items {
		if _, err := s.Put(context.Background(), p, []byte(v)); err != nil {
			t.Fatalf("Put %s: %v", p, err)
		}
	}
}

func readRecord(t *testing.T, s *Store, p string) record {
	t.Helper()
	var rec record
	if err := readJSON(s.file(p), &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

func writeRecordAt(t *testing.T, s *Store, p string, rec record) {
	t.Helper()
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.file(p), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, newKeys(t), t.TempDir(), "1000")
	putAll(t, s, map[string]string{"a/token": "one", "b/token": "two"})
	if v, err := s.Put(ctx, "a/token", []byte("three")); err != nil || v != 2 {
		t.Fatalf("second Put = %d, %v", v, err)
	}
	got, m, err := s.Get(ctx, "a/token")
	if err != nil || string(got) != "three" || m.Version != 2 || m.Backend != Name {
		t.Fatalf("Get = %q %+v %v", got, m, err)
	}
	entries, err := s.List(ctx, "a/")
	if err != nil || len(entries) != 1 || entries[0].Path != "a/token" || !entries[0].Exists {
		t.Fatalf("List = %+v %v", entries, err)
	}
	if all, _ := s.List(ctx, ""); len(all) != 2 {
		t.Fatalf("List all = %d, want 2", len(all))
	}
	if err := s.Delete(ctx, "a/token"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Get(ctx, "a/token"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("Get after Delete = %v", err)
	}
	if err := s.Delete(ctx, "a/token"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("second Delete = %v", err)
	}
}

func TestStoreNeverWritesPlaintext(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, newKeys(t), dir, "1000")
	putAll(t, s, map[string]string{"svc/key": "super-secret-value"})
	files, _ := os.ReadDir(dir)
	for _, f := range files {
		b, _ := os.ReadFile(filepath.Join(dir, f.Name()))
		if bytes.Contains(b, []byte("super-secret-value")) {
			t.Fatalf("%s holds the plaintext", f.Name())
		}
		if info, _ := f.Info(); info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v", f.Name(), info.Mode().Perm())
		}
	}
}

func TestStoreAADChecked(t *testing.T) {
	ctx := context.Background()
	h := newKeys(t)
	dir := t.TempDir()
	s := newStore(t, h, dir, "1000")
	putAll(t, s, map[string]string{"a": "alpha", "b": "beta"})

	t.Run("record moved to another path", func(t *testing.T) {
		recA := readRecord(t, s, "a")
		writeRecordAt(t, s, "b", recA)
		if _, _, err := s.Get(ctx, "b"); !errors.Is(err, ErrAAD) {
			t.Fatalf("Get = %v, want ErrAAD", err)
		}
		putAll(t, s, map[string]string{"b": "beta"})
	})
	t.Run("record renamed in place", func(t *testing.T) {
		recA := readRecord(t, s, "a")
		recA.Path = "b"
		writeRecordAt(t, s, "b", recA)
		if _, _, err := s.Get(ctx, "b"); !errors.Is(err, ErrAAD) {
			t.Fatalf("Get = %v, want ErrAAD", err)
		}
		putAll(t, s, map[string]string{"b": "beta"})
	})
	t.Run("version rolled back", func(t *testing.T) {
		rec := readRecord(t, s, "a")
		rec.Version++
		writeRecordAt(t, s, "a", rec)
		if _, _, err := s.Get(ctx, "a"); !errors.Is(err, ErrAAD) {
			t.Fatalf("Get = %v, want ErrAAD", err)
		}
	})
	t.Run("value ciphertext swapped", func(t *testing.T) {
		putAll(t, s, map[string]string{"a": "alpha", "c": "gamma"})
		a, c := readRecord(t, s, "a"), readRecord(t, s, "c")
		a.Nonce, a.CT = c.Nonce, c.CT
		writeRecordAt(t, s, "a", a)
		if _, _, err := s.Get(ctx, "a"); !errors.Is(err, ErrAAD) {
			t.Fatalf("Get = %v, want ErrAAD", err)
		}
	})
	t.Run("another partition", func(t *testing.T) {
		putAll(t, s, map[string]string{"a": "alpha"})
		other := newStore(t, h, dir, "1001")
		if _, _, err := other.Get(ctx, "a"); !errors.Is(err, ErrAAD) {
			t.Fatalf("a partition reading another's record = %v, want ErrAAD", err)
		}
	})
	t.Run("unknown master key", func(t *testing.T) {
		rec := readRecord(t, s, "a")
		rec.KID = "feedface"
		writeRecordAt(t, s, "a", rec)
		if _, _, err := s.Get(ctx, "a"); err == nil {
			t.Fatal("a record wrapped by an unknown master key must not open")
		}
	})
}

func TestRewrapKeepsCiphertext(t *testing.T) {
	ctx := context.Background()
	h := newKeys(t)
	s := newStore(t, h, t.TempDir(), "1000")
	putAll(t, s, map[string]string{"a": "alpha", "b/c": "beta"})
	before := readRecord(t, s, "a")

	var rewrapped int
	if err := h.Rotate(func(oldKEK, newKEK keys.KEKFunc, newKID string) error {
		n, err := s.Rewrap(oldKEK("1000"), newKEK("1000"), newKID)
		rewrapped = n
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if rewrapped != 2 {
		t.Fatalf("rewrapped %d records, want 2", rewrapped)
	}
	after := readRecord(t, s, "a")
	if !bytes.Equal(before.CT, after.CT) || !bytes.Equal(before.Nonce, after.Nonce) {
		t.Fatal("rotation re-encrypted the value")
	}
	if before.KID == after.KID || after.KID != h.KeyID() {
		t.Fatal("the data key was not moved to the new master key")
	}
	for p, want := range map[string]string{"a": "alpha", "b/c": "beta"} {
		if got, _, err := s.Get(ctx, p); err != nil || string(got) != want {
			t.Fatalf("Get %s after rotation = %q, %v", p, got, err)
		}
	}
	// Running the rewrap again changes nothing.
	n, err := s.Rewrap(nil, nil, h.KeyID())
	if err != nil || n != 0 {
		t.Fatalf("repeat Rewrap = %d, %v", n, err)
	}
}

func TestRewrapRejectsWrongOldKey(t *testing.T) {
	h := newKeys(t)
	s := newStore(t, h, t.TempDir(), "1000")
	putAll(t, s, map[string]string{"a": "alpha"})
	if _, err := s.Rewrap(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), "new"); !errors.Is(err, ErrAAD) {
		t.Fatalf("Rewrap with the wrong old key = %v, want ErrAAD", err)
	}
}

func TestStoreValidation(t *testing.T) {
	ctx := context.Background()
	h := newKeys(t)
	if _, err := Open(t.TempDir(), "", h); err == nil {
		t.Fatal("an empty partition name must be refused")
	}
	s := newStore(t, h, t.TempDir(), "1000")
	for _, p := range []string{"", "/abs", "../x", "a/../b", "a//b", "a\x00b", string(make([]byte, maxPathLen+1))} {
		if _, err := s.Put(ctx, p, []byte("v")); err == nil {
			t.Fatalf("Put(%q) must be refused", p)
		}
		if _, _, err := s.Get(ctx, p); err == nil {
			t.Fatalf("Get(%q) must be refused", p)
		}
		if err := s.Delete(ctx, p); err == nil {
			t.Fatalf("Delete(%q) must be refused", p)
		}
	}
	if _, _, err := s.Get(ctx, "missing"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("Get missing = %v", err)
	}
	if err := os.WriteFile(s.file("junk"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Get(ctx, "junk"); err == nil {
		t.Fatal("a corrupt record must be refused")
	}
	if list, err := s.List(ctx, ""); err != nil || len(list) != 0 {
		t.Fatalf("List skips unreadable records: %v %v", list, err)
	}
}

func TestStoreWriteFailures(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("directory permissions do not bind root")
	}
	ctx := context.Background()
	dir := t.TempDir()
	s := newStore(t, newKeys(t), dir, "1000")
	putAll(t, s, map[string]string{"a": "alpha"})
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()
	if _, err := s.Put(ctx, "b", []byte("v")); err == nil {
		t.Fatal("Put into a read-only store must fail")
	}
	if err := s.Delete(ctx, "a"); err == nil {
		t.Fatal("Delete from a read-only store must fail")
	}
}
