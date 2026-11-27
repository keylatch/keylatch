package vault_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/vault"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
	vpath "github.com/keylatch/keylatch/internal/vault/path"
)

const scCanon = "default/ai/openrouter/api_key"

var scRegistryOnce sync.Once

func scCtx() context.Context {
	return audit.WithEmitter(context.Background(), &recordingEmitter{})
}

func scInitRegistry(t *testing.T) {
	t.Helper()
	scRegistryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "keylatch-vault-registry-")
		if err != nil {
			t.Fatal(err)
		}
		if err := registry.InitFromConfig(context.Background(), func(k string) string {
			if k == "KEYLATCH_CONFIG_DIR" {
				return dir
			}
			return ""
		}); err != nil {
			t.Fatalf("registry init: %v", err)
		}
	})
}

func scSkipNoPerms(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("directory permission semantics differ")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
}

func scRotate(t *testing.T, cfg config.Config, env func(string) string, n int, m vmeta.Meta) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := vault.RotateValue(scCtx(), scCanon, []byte("value"), m, cfg, env); err != nil {
			t.Fatalf("RotateValue: %v", err)
		}
	}
}

func TestVersionAPIs_RejectInvalidPaths(t *testing.T) {
	resetDispatch(t)
	cfg := testCfg(t)
	env := testEnv(t)
	ctx := scCtx()

	for _, p := range []string{"default/ai/../api_key", "../../etc/passwd", "default/ai/openrouter/key\x00x", ""} {
		checks := map[string]error{}
		_, checks["GetMeta"] = vault.GetMeta(ctx, p, cfg, env)
		checks["SetMeta"] = vault.SetMeta(ctx, p, vmeta.Meta{}, cfg, env)
		_, checks["RotateValue"] = vault.RotateValue(ctx, p, []byte("v"), vmeta.Meta{}, cfg, env)
		_, _, checks["GetVersion"] = vault.GetVersion(ctx, p, 1, cfg, env)
		checks["DestroyVersion"] = vault.DestroyVersion(ctx, p, 1, cfg, env)
		checks["Rollback"] = vault.Rollback(ctx, p, 1, cfg, env)
		for name, err := range checks {
			if !errors.Is(err, vpath.ErrInvalidPath) {
				t.Errorf("%s(%q): want ErrInvalidPath, got %v", name, p, err)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, "values")); !os.IsNotExist(err) {
		t.Fatalf("invalid paths created storage: %v", err)
	}
}

func TestVersionAPIs_DispatchFailurePropagates(t *testing.T) {
	resetDispatch(t)
	cfg := config.Default()
	cfg.Backend = "sops"
	env := fakeEnv(map[string]string{})
	ctx := scCtx()

	checks := map[string]error{}
	_, checks["GetMeta"] = vault.GetMeta(ctx, scCanon, cfg, env)
	checks["SetMeta"] = vault.SetMeta(ctx, scCanon, vmeta.Meta{SchemaVersion: vmeta.CurrentSchemaVersion, Accessor: vmeta.NewAccessor(), CurrentVersion: 1}, cfg, env)
	_, checks["ListMeta"] = vault.ListMeta(ctx, "", cfg, env)
	_, checks["RotateValue"] = vault.RotateValue(ctx, scCanon, []byte("v"), vmeta.Meta{}, cfg, env)
	_, _, checks["GetVersion"] = vault.GetVersion(ctx, scCanon, 1, cfg, env)
	checks["DestroyVersion"] = vault.DestroyVersion(ctx, scCanon, 1, cfg, env)
	checks["Rollback"] = vault.Rollback(ctx, scCanon, 1, cfg, env)
	checks["Set"] = vault.Set(ctx, scCanon, []byte("v"), backend.Meta{}, cfg, env)
	checks["Delete"] = vault.Delete(ctx, scCanon, cfg, env)
	_, checks["List"] = vault.List(ctx, "", cfg, env)
	for name, err := range checks {
		if err == nil {
			t.Errorf("%s succeeded with unavailable backend", name)
		}
	}
}

func TestShorthandPaths_ResolveThroughRegistry(t *testing.T) {
	scInitRegistry(t)
	resetDispatch(t)
	cfg := testCfg(t)
	env := testEnv(t)
	ctx := scCtx()

	if _, err := vault.RotateValue(ctx, "openrouter.api_key", []byte("v"), vmeta.Meta{}, cfg, env); err != nil {
		t.Fatalf("RotateValue shorthand: %v", err)
	}
	m, err := vault.GetMeta(ctx, "openrouter.api_key", cfg, env)
	if err != nil {
		t.Fatal(err)
	}
	if m.Path != scCanon || m.CurrentVersion != 1 {
		t.Fatalf("meta = %+v", m)
	}
	if _, err := vault.GetMeta(ctx, "no-such-provider-xyz.api_key", cfg, env); !errors.Is(err, vpath.ErrUnknownProvider) {
		t.Fatalf("unknown provider: %v", err)
	}
}

func TestSetMetaAndListMeta(t *testing.T) {
	resetDispatch(t)
	cfg := testCfg(t)
	env := testEnv(t)
	ctx := scCtx()

	paths := []string{"default/ai/zeta/key", "default/ai/alpha/key", "default/ai/mid/key"}
	for _, p := range paths {
		m := vmeta.Meta{
			SchemaVersion:  vmeta.CurrentSchemaVersion,
			Path:           "ignored/overwritten/by/vault",
			Accessor:       vmeta.NewAccessor(),
			CurrentVersion: 1,
			Owner:          "ops",
		}
		before := time.Now().Add(-time.Second)
		if err := vault.SetMeta(ctx, p, m, cfg, env); err != nil {
			t.Fatalf("SetMeta %s: %v", p, err)
		}
		got, err := vault.GetMeta(ctx, p, cfg, env)
		if err != nil {
			t.Fatal(err)
		}
		if got.Path != p || got.Owner != "ops" || got.UpdatedAt.Before(before) {
			t.Fatalf("stored meta = %+v", got)
		}
	}

	list, err := vault.ListMeta(ctx, "", cfg, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 || list[0].Path != "default/ai/alpha/key" || list[2].Path != "default/ai/zeta/key" {
		t.Fatalf("ListMeta not sorted: %v", list)
	}

	bad := vmeta.Meta{SchemaVersion: vmeta.CurrentSchemaVersion, Accessor: vmeta.NewAccessor(), CurrentVersion: 0}
	if err := vault.SetMeta(ctx, scCanon, bad, cfg, env); !errors.Is(err, vmeta.ErrInvalidVersion) {
		t.Fatalf("invalid meta: %v", err)
	}
	if _, err := vault.GetMeta(ctx, scCanon, cfg, env); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("invalid meta was stored: %v", err)
	}
}

func TestListMeta_BackendErrorPropagates(t *testing.T) {
	scSkipNoPerms(t)
	resetDispatch(t)
	cfg := testCfg(t)
	env := testEnv(t)
	scRotate(t, cfg, env, 1, vmeta.Meta{})
	metaDir := filepath.Join(cfg.DataDir, "metadata", "default", "ai")
	if err := os.Chmod(metaDir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(metaDir, 0o700) })
	if _, err := vault.ListMeta(scCtx(), "", cfg, env); err == nil {
		t.Fatal("ListMeta succeeded on unreadable metadata")
	}
}

func TestRotateValue_MergesCallerMetadata(t *testing.T) {
	resetDispatch(t)
	cfg := testCfg(t)
	env := testEnv(t)
	ctx := scCtx()

	issued := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	expires := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	scRotate(t, cfg, env, 1, vmeta.Meta{Custom: map[string]string{"a": "1"}})
	scRotate(t, cfg, env, 1, vmeta.Meta{
		Owner:            "team-x",
		Scope:            "read",
		Purpose:          "ci",
		RotationHint:     "monthly",
		IssuedAt:         &issued,
		ExpiresAt:        &expires,
		Custom:           map[string]string{"b": "2"},
		SharedRecipients: []string{"r1"},
	})

	m, err := vault.GetMeta(ctx, scCanon, cfg, env)
	if err != nil {
		t.Fatal(err)
	}
	if m.Owner != "team-x" || m.Scope != "read" || m.Purpose != "ci" || m.RotationHint != "monthly" {
		t.Fatalf("scalar fields not merged: %+v", m)
	}
	if m.IssuedAt == nil || !m.IssuedAt.Equal(issued) || m.ExpiresAt == nil || !m.ExpiresAt.Equal(expires) {
		t.Fatalf("times not merged: %v %v", m.IssuedAt, m.ExpiresAt)
	}
	if m.Custom["a"] != "1" || m.Custom["b"] != "2" {
		t.Fatalf("custom not merged: %v", m.Custom)
	}
	if len(m.SharedRecipients) != 1 || m.CurrentVersion != 2 || len(m.Versions) != 2 {
		t.Fatalf("meta = %+v", m)
	}
	if m.Versions[1].CreatedBy != "team-x" || m.Versions[1].AAD.Version != 2 || m.Versions[1].AAD.Path != scCanon {
		t.Fatalf("version meta = %+v", m.Versions[1])
	}
}

func TestRotateValue_StorageFailures(t *testing.T) {
	t.Run("corrupt metadata", func(t *testing.T) {
		resetDispatch(t)
		cfg := testCfg(t)
		env := testEnv(t)
		scRotate(t, cfg, env, 1, vmeta.Meta{})
		metaFile := filepath.Join(cfg.DataDir, "metadata", "default", "ai", "openrouter", "api_key.json")
		if err := os.WriteFile(metaFile, []byte("{corrupt"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := vault.RotateValue(scCtx(), scCanon, []byte("v"), vmeta.Meta{}, cfg, env)
		if err == nil || !strings.Contains(err.Error(), "RotateValue GetMeta") {
			t.Fatalf("want GetMeta error, got %v", err)
		}
	})

	t.Run("value directory blocked", func(t *testing.T) {
		resetDispatch(t)
		cfg := testCfg(t)
		env := testEnv(t)
		blocker := filepath.Join(cfg.DataDir, "values", "default", "ai", "openrouter", "api_key")
		if err := os.MkdirAll(filepath.Dir(blocker), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(blocker, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := vault.RotateValue(scCtx(), scCanon, []byte("v"), vmeta.Meta{}, cfg, env)
		if err == nil || !strings.Contains(err.Error(), "RotateValue SetVersioned") {
			t.Fatalf("want SetVersioned error, got %v", err)
		}
		if _, err := vault.GetMeta(scCtx(), scCanon, cfg, env); !errors.Is(err, backend.ErrNotFound) {
			t.Fatalf("metadata written despite value failure: %v", err)
		}
	})

	t.Run("metadata write failure removes orphan value", func(t *testing.T) {
		scSkipNoPerms(t)
		resetDispatch(t)
		cfg := testCfg(t)
		env := testEnv(t)
		scRotate(t, cfg, env, 1, vmeta.Meta{})
		metaDir := filepath.Join(cfg.DataDir, "metadata", "default", "ai", "openrouter")
		if err := os.Chmod(metaDir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(metaDir, 0o700) })

		_, err := vault.RotateValue(scCtx(), scCanon, []byte("v2"), vmeta.Meta{}, cfg, env)
		if err == nil || !strings.Contains(err.Error(), "RotateValue SetMeta") {
			t.Fatalf("want SetMeta error, got %v", err)
		}
		orphan := filepath.Join(cfg.DataDir, "values", "default", "ai", "openrouter", "api_key", "2")
		if _, err := os.Stat(orphan); !os.IsNotExist(err) {
			t.Fatalf("orphaned version 2 left on disk: %v", err)
		}
		m, err := vault.GetMeta(scCtx(), scCanon, cfg, env)
		if err != nil || m.CurrentVersion != 1 {
			t.Fatalf("meta after failed rotate: %+v %v", m, err)
		}
	})
}

func TestGetVersion_StateChecks(t *testing.T) {
	resetDispatch(t)
	cfg := testCfg(t)
	env := testEnv(t)
	ctx := scCtx()

	if _, _, err := vault.GetVersion(ctx, scCanon, 1, cfg, env); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("missing path: %v", err)
	}
	scRotate(t, cfg, env, 3, vmeta.Meta{MaxVersions: 2})

	if _, _, err := vault.GetVersion(ctx, scCanon, 1, cfg, env); !errors.Is(err, vault.ErrVersionNotFound) {
		t.Fatalf("evicted version: %v", err)
	}
	if _, _, err := vault.GetVersion(ctx, scCanon, 99, cfg, env); !errors.Is(err, vault.ErrVersionNotFound) {
		t.Fatalf("unknown version: %v", err)
	}
	val, vm, err := vault.GetVersion(ctx, scCanon, 3, cfg, env)
	if err != nil || string(val) != "value" || vm.Version != 3 {
		t.Fatalf("current version: %q %+v %v", val, vm, err)
	}

	valuesDir := filepath.Join(cfg.DataDir, "values", "default", "ai", "openrouter", "api_key")
	if err := os.Remove(filepath.Join(valuesDir, "2")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := vault.GetVersion(ctx, scCanon, 2, cfg, env); err == nil {
		t.Fatal("missing ciphertext returned a value")
	}
	if err := vault.Rollback(ctx, scCanon, 2, cfg, env); err == nil || !strings.Contains(err.Error(), "Rollback GetVersioned") {
		t.Fatalf("rollback of missing ciphertext: %v", err)
	}
}

func TestSoftDeletedVersionBlocksReadAndRollback(t *testing.T) {
	resetDispatch(t)
	cfg := testCfg(t)
	env := testEnv(t)
	ctx := scCtx()
	scRotate(t, cfg, env, 2, vmeta.Meta{})

	m, err := vault.GetMeta(ctx, scCanon, cfg, env)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	m.Versions[0].DeletedAt = &now
	if err := vault.SetMeta(ctx, scCanon, m, cfg, env); err != nil {
		t.Fatal(err)
	}
	if _, _, err := vault.GetVersion(ctx, scCanon, 1, cfg, env); !errors.Is(err, vault.ErrVersionDeleted) {
		t.Fatalf("GetVersion: %v", err)
	}
	if err := vault.Rollback(ctx, scCanon, 1, cfg, env); !errors.Is(err, vault.ErrVersionDeleted) {
		t.Fatalf("Rollback: %v", err)
	}
}

func TestDestroyAndRollback_StateChecks(t *testing.T) {
	resetDispatch(t)
	cfg := testCfg(t)
	env := testEnv(t)
	ctx := scCtx()

	if err := vault.DestroyVersion(ctx, scCanon, 1, cfg, env); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("destroy on missing path: %v", err)
	}
	if err := vault.Rollback(ctx, scCanon, 1, cfg, env); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("rollback on missing path: %v", err)
	}
	scRotate(t, cfg, env, 3, vmeta.Meta{})

	if err := vault.DestroyVersion(ctx, scCanon, 42, cfg, env); !errors.Is(err, vault.ErrVersionNotFound) {
		t.Fatalf("destroy unknown: %v", err)
	}
	if err := vault.Rollback(ctx, scCanon, 42, cfg, env); !errors.Is(err, vault.ErrVersionNotFound) {
		t.Fatalf("rollback unknown: %v", err)
	}
	if err := vault.DestroyVersion(ctx, scCanon, 1, cfg, env); err != nil {
		t.Fatal(err)
	}
	if err := vault.DestroyVersion(ctx, scCanon, 1, cfg, env); !errors.Is(err, vault.ErrVersionDestroyed) {
		t.Fatalf("double destroy: %v", err)
	}
	m, err := vault.GetMeta(ctx, scCanon, cfg, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.DestroyedVersions) != 1 || m.DestroyedVersions[0] != 1 {
		t.Fatalf("DestroyedVersions = %v", m.DestroyedVersions)
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, "values", "default", "ai", "openrouter", "api_key", "1")); !os.IsNotExist(err) {
		t.Fatalf("destroyed ciphertext still present: %v", err)
	}

	if err := vault.Rollback(ctx, scCanon, 2, cfg, env); err != nil {
		t.Fatal(err)
	}
	m, err = vault.GetMeta(ctx, scCanon, cfg, env)
	if err != nil {
		t.Fatal(err)
	}
	if m.CurrentVersion != 4 || m.Custom["rolled_back_from"] != "2" {
		t.Fatalf("rollback meta = %+v", m)
	}
}

func TestVaultOps_ErrorClassInAudit(t *testing.T) {
	scSkipNoPerms(t)
	resetDispatch(t)
	cfg := testCfg(t)
	env := testEnv(t)
	rec := &recordingEmitter{}
	ctx := audit.WithEmitter(context.Background(), rec)

	if err := vault.Set(ctx, scCanon, []byte("v"), backend.Meta{Path: scCanon, Backend: "file", Version: 1}, cfg, env); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfg.DataDir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(cfg.DataDir, 0o700) })

	if _, err := vault.Get(ctx, scCanon, cfg, env); err == nil {
		t.Fatal("Get succeeded on unreadable store")
	}
	ev, ok := rec.last()
	if !ok || ev.Action != audit.ActionRead || ev.Outcome != audit.OutcomeError {
		t.Fatalf("event = %+v", ev)
	}
	if ev.Extra["error_class"] != "error" {
		t.Fatalf("error_class = %v, want error", ev.Extra["error_class"])
	}
	for k, v := range ev.Extra {
		if s, ok := v.(string); ok && strings.Contains(s, cfg.DataDir) {
			t.Fatalf("audit extra %q leaks filesystem path", k)
		}
	}
}
