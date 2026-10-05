//go:build !darwin

package keychain

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/vault/meta"
)

func TestStub_OpenUnavailable(t *testing.T) {
	kb, err := Open(Options{KeychainPath: "/nonexistent"})
	if !errors.Is(err, backend.ErrUnavailable) {
		t.Fatalf("Open err = %v, want ErrUnavailable", err)
	}
	if kb != nil {
		t.Fatalf("Open returned non-nil backend on non-darwin")
	}
}

func TestStub_DataMethodsFailClosed(t *testing.T) {
	ctx := context.Background()
	k := &KeychainBackend{}
	if k.Name() != "keychain" {
		t.Errorf("Name = %q", k.Name())
	}
	if k.ID() != "keychain:" {
		t.Errorf("ID = %q", k.ID())
	}
	if caps := k.Capabilities(); len(caps) != 0 {
		t.Errorf("Capabilities = %v, want none", caps)
	}
	if err := k.Close(); err != nil {
		t.Errorf("Close = %v", err)
	}

	val, _, err := k.Get(ctx, "a/b")
	if !errors.Is(err, backend.ErrUnavailable) || val != nil {
		t.Errorf("Get = %q, %v", val, err)
	}
	unavailable := map[string]error{
		"Set":            k.Set(ctx, "a/b", []byte("v"), backend.Meta{}),
		"Delete":         k.Delete(ctx, "a/b"),
		"VerifyACL":      k.VerifyACL(ctx),
		"RepairACL":      k.RepairACL(ctx),
		"RepairItemACLs": k.RepairItemACLs(ctx),
		"Init":           k.Init(ctx, "pw"),
	}
	entries, err := k.List(ctx, "")
	unavailable["List"] = err
	if entries != nil {
		t.Errorf("List entries = %v", entries)
	}
	for name, err := range unavailable {
		if !errors.Is(err, backend.ErrUnavailable) {
			t.Errorf("%s err = %v, want ErrUnavailable", name, err)
		}
	}

	notSupported := map[string]error{
		"SetMeta":         k.SetMeta(ctx, "a/b", meta.Meta{}),
		"SetVersioned":    k.SetVersioned(ctx, "a/b", 1, []byte("v")),
		"DeleteVersioned": k.DeleteVersioned(ctx, "a/b", 1),
	}
	_, notSupported["GetMeta"] = k.GetMeta(ctx, "a/b")
	ms, err := k.ListMeta(ctx, "")
	notSupported["ListMeta"] = err
	if ms != nil {
		t.Errorf("ListMeta = %v", ms)
	}
	v, err := k.GetVersioned(ctx, "a/b", 1)
	notSupported["GetVersioned"] = err
	if v != nil {
		t.Errorf("GetVersioned = %q", v)
	}
	for name, err := range notSupported {
		if !errors.Is(err, backend.ErrNotSupported) {
			t.Errorf("%s err = %v, want ErrNotSupported", name, err)
		}
	}
}

func TestStub_AcquireFlockNoop(t *testing.T) {
	release, err := acquireFlock(filepath.Join(t.TempDir(), "lock"))
	if err != nil {
		t.Fatalf("acquireFlock: %v", err)
	}
	release()
}

func TestStub_RegisteredFactoryUnavailable(t *testing.T) {
	factory, ok := backend.Default.Get("keychain")
	if !ok {
		t.Fatal("keychain factory not registered")
	}
	b, err := factory(context.Background(), backend.BackendConfig{Name: "keychain"})
	if !errors.Is(err, backend.ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if b != nil {
		t.Fatalf("backend non-nil")
	}
	if !strings.Contains(err.Error(), "requires macOS") {
		t.Errorf("err %q lacks platform hint", err)
	}
}

func TestDefaultDBPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	p, err := DefaultDBPath()
	if err != nil {
		t.Fatalf("DefaultDBPath: %v", err)
	}
	if want := home + "/.keylatch/keylatch.keychain-db"; p != want {
		t.Errorf("path = %q, want %q", p, want)
	}

	t.Setenv("HOME", "")
	if _, err := DefaultDBPath(); err == nil || !strings.Contains(err.Error(), "resolve home") {
		t.Errorf("empty HOME err = %v", err)
	}
}
