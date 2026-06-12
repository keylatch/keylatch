package infisical_test

import (
	"context"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/infisical"
	"github.com/keylatch/keylatch/internal/vault/meta"
)

func openTestBackend(t *testing.T, secrets map[string]string) *infisical.InfisicalBackend {
	t.Helper()
	srv := newInfisicalTestServer(secrets)
	t.Cleanup(srv.Close)
	b, err := infisical.Open(infisical.Options{
		BaseURL:      srv.URL,
		ClientID:     "cid",
		ClientSecret: "csecret",
		WorkspaceID:  "ws-123",
		Environment:  "dev",
		SecretPath:   "/",
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return b
}

func TestInfisicalSet_CreateAndReadBack(t *testing.T) {
	secrets := map[string]string{}
	b := openTestBackend(t, secrets)
	ctx := context.Background()

	if err := b.Set(ctx, "NEW_SECRET", []byte("v1"), backend.Meta{}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	val, m, err := b.Get(ctx, "NEW_SECRET")
	if err != nil {
		t.Fatalf("Get after Set: %v", err)
	}
	if string(val) != "v1" {
		t.Errorf("value = %q", val)
	}
	if m.Backend != "infisical" {
		t.Errorf("meta backend = %q", m.Backend)
	}
}

func TestInfisicalDelete(t *testing.T) {
	secrets := map[string]string{"GONE": "x"}
	b := openTestBackend(t, secrets)
	ctx := context.Background()

	if err := b.Delete(ctx, "GONE"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, _, err := b.Get(ctx, "GONE"); !errors.Is(err, backend.ErrNotFound) {
		t.Errorf("Get after delete: %v", err)
	}
	// Deleting a missing secret maps to ErrNotFound.
	if err := b.Delete(ctx, "NEVER"); !errors.Is(err, backend.ErrNotFound) {
		t.Errorf("Delete missing: %v", err)
	}
}

func TestInfisicalIdentityAndStubs(t *testing.T) {
	b := openTestBackend(t, map[string]string{})
	ctx := context.Background()

	if b.Name() != "infisical" {
		t.Errorf("Name = %q", b.Name())
	}
	if b.ID() == "" {
		t.Error("ID empty")
	}
	if b.Capabilities() == nil {
		t.Log("Capabilities nil (acceptable for this backend)")
	}
	if err := b.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}

	if _, err := b.GetMeta(ctx, "p"); !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("GetMeta: %v", err)
	}
	if err := b.SetMeta(ctx, "p", meta.Meta{}); !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("SetMeta: %v", err)
	}
	if _, err := b.ListMeta(ctx, "p"); !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("ListMeta: %v", err)
	}
	if _, err := b.GetVersioned(ctx, "p", 1); !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("GetVersioned: %v", err)
	}
	if err := b.SetVersioned(ctx, "p", 1, nil); !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("SetVersioned: %v", err)
	}
	if err := b.DeleteVersioned(ctx, "p", 1); !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("DeleteVersioned: %v", err)
	}
}
