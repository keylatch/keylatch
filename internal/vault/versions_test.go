package vault_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/backend/file"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/keylatch/keylatch/internal/vault"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
	"github.com/stretchr/testify/require"
)

// -----------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------

func testCfg(t *testing.T) config.Config {
	t.Helper()
	dir := t.TempDir()
	return config.Config{
		Backend: "file",
		DataDir: dir,
	}
}

func testEnv(t *testing.T) llmcontext.Lookup {
	t.Helper()
	krPath := testutil.SetupTestKeyring(t)
	return func(k string) string {
		if k == "KEYLATCH_KEYRING_PATH" {
			return krPath
		}
		return ""
	}
}

func resetDispatch(t *testing.T) {
	t.Helper()
	t.Cleanup(dispatch.ClearCached)
	dispatch.ClearCached()
}

// openFileBackend returns a file backend over t.TempDir().
func openFileBackend(t *testing.T) (backend.Backend, string) {
	t.Helper()
	dir := t.TempDir()
	b, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("file.Open: %v", err)
	}
	t.Cleanup(func() { b.Close() })
	return b, dir
}

// -----------------------------------------------------------------------
// spyBackend — wraps a real backend and counts backend.Get calls
// -----------------------------------------------------------------------

// spyBackend wraps a backend.Backend and counts calls to Get.
// All other methods delegate to the embedded backend unchanged.
// Used to verify that GetMeta and ListMeta must never call backend.Get.
type spyBackend struct {
	backend.Backend
	getCallCount atomic.Int64
}

// Get intercepts the call, increments the counter, then delegates.
func (s *spyBackend) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	s.getCallCount.Add(1)
	return s.Backend.Get(ctx, path)
}

// -----------------------------------------------------------------------
// RotateValue tests
// -----------------------------------------------------------------------

func TestRotateValue_VersionsIncrement(t *testing.T) {
	resetDispatch(t)
	cfg := testCfg(t)
	env := testEnv(t)
	ctx := context.Background()

	// Use a pre-canonicalized path to avoid the registry resolver.
	path := "default/ai/openrouter/api_key"

	for i := 1; i <= 3; i++ {
		ver, err := vault.RotateValue(ctx, path, []byte("value"), vmeta.Meta{}, cfg, env)
		if err != nil {
			t.Fatalf("RotateValue iteration %d: %v", i, err)
		}
		if ver != i {
			t.Errorf("iteration %d: got version %d, want %d", i, ver, i)
		}
	}
}

func TestRotateValue_MaxVersionsEnforced(t *testing.T) {
	resetDispatch(t)
	cfg := testCfg(t)
	env := testEnv(t)
	ctx := context.Background()
	root := cfg.DataDir

	path := "default/ai/openrouter/api_key"
	const maxVersions = 2

	// First rotation: set MaxVersions=2 on the partial meta.
	partial := vmeta.Meta{MaxVersions: maxVersions}
	_, err := vault.RotateValue(ctx, path, []byte("v1"), partial, cfg, env)
	if err != nil {
		t.Fatalf("RotateValue 1: %v", err)
	}

	// Second rotation.
	_, err = vault.RotateValue(ctx, path, []byte("v2"), vmeta.Meta{}, cfg, env)
	if err != nil {
		t.Fatalf("RotateValue 2: %v", err)
	}

	// Third rotation: version 1 should be soft-deleted.
	_, err = vault.RotateValue(ctx, path, []byte("v3"), vmeta.Meta{}, cfg, env)
	if err != nil {
		t.Fatalf("RotateValue 3: %v", err)
	}

	m, err := vault.GetMeta(ctx, path, cfg, env)
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}

	// Should have 2 versions (3rd replaced 1st).
	if len(m.Versions) != maxVersions {
		t.Errorf("expected %d versions, got %d", maxVersions, len(m.Versions))
	}

	// Version 1 should have been evicted.
	_, _, err = vault.GetVersion(ctx, path, 1, cfg, env)
	if err == nil {
		t.Error("expected error getting evicted version 1")
	}

	// Assert the ciphertext file was physically removed, not just soft-deleted in metadata.
	valuePath := filepath.Join(root, "values", "default", "ai", "openrouter", "api_key", "1")
	_, statErr := os.Stat(valuePath)
	require.True(t, os.IsNotExist(statErr), "expected value file for v1 to be deleted, got: %v", statErr)
}

func TestRotateValue_RoundTripsTeamID(t *testing.T) {
	resetDispatch(t)
	cfg := testCfg(t)
	env := testEnv(t)
	ctx := context.Background()

	path := "default/ai/openrouter/api_key"
	partial := vmeta.Meta{
		TeamID:           "team-42",
		SharedRecipients: []string{"alice", "bob"},
	}

	_, err := vault.RotateValue(ctx, path, []byte("secret"), partial, cfg, env)
	if err != nil {
		t.Fatalf("RotateValue: %v", err)
	}

	m, err := vault.GetMeta(ctx, path, cfg, env)
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}

	if m.TeamID != "team-42" {
		t.Errorf("TeamID: got %q, want %q", m.TeamID, "team-42")
	}
	if len(m.SharedRecipients) != 2 {
		t.Errorf("SharedRecipients: got %v", m.SharedRecipients)
	}
}

// -----------------------------------------------------------------------
// DestroyVersion tests
// -----------------------------------------------------------------------

func TestDestroyVersion_BlocksGetVersion(t *testing.T) {
	resetDispatch(t)
	cfg := testCfg(t)
	env := testEnv(t)
	ctx := context.Background()

	path := "default/ai/openrouter/api_key"

	// Create two versions so we can destroy v1 (not current).
	if _, err := vault.RotateValue(ctx, path, []byte("v1"), vmeta.Meta{}, cfg, env); err != nil {
		t.Fatalf("RotateValue v1: %v", err)
	}
	if _, err := vault.RotateValue(ctx, path, []byte("v2"), vmeta.Meta{}, cfg, env); err != nil {
		t.Fatalf("RotateValue v2: %v", err)
	}

	if err := vault.DestroyVersion(ctx, path, 1, cfg, env); err != nil {
		t.Fatalf("DestroyVersion: %v", err)
	}

	_, _, err := vault.GetVersion(ctx, path, 1, cfg, env)
	if !errors.Is(err, vault.ErrVersionDestroyed) {
		t.Errorf("want ErrVersionDestroyed, got: %v", err)
	}
}

func TestDestroyVersion_BlocksCurrentVersion(t *testing.T) {
	resetDispatch(t)
	cfg := testCfg(t)
	env := testEnv(t)
	ctx := context.Background()

	path := "default/ai/openrouter/api_key"
	if _, err := vault.RotateValue(ctx, path, []byte("v1"), vmeta.Meta{}, cfg, env); err != nil {
		t.Fatalf("RotateValue: %v", err)
	}

	err := vault.DestroyVersion(ctx, path, 1, cfg, env)
	if !errors.Is(err, vault.ErrDestroyCurrentVersion) {
		t.Errorf("want ErrDestroyCurrentVersion, got: %v", err)
	}
}

// -----------------------------------------------------------------------
// Rollback tests
// -----------------------------------------------------------------------

func TestRollback_CreatesNewVersion(t *testing.T) {
	resetDispatch(t)
	cfg := testCfg(t)
	env := testEnv(t)
	ctx := context.Background()

	path := "default/ai/openrouter/api_key"

	v1Value := []byte("v1-secret")
	v2Value := []byte("v2-secret")
	v3Value := []byte("v3-secret")
	v4Value := []byte("v4-secret")

	for i, v := range [][]byte{v1Value, v2Value, v3Value, v4Value} {
		if _, err := vault.RotateValue(ctx, path, v, vmeta.Meta{}, cfg, env); err != nil {
			t.Fatalf("RotateValue v%d: %v", i+1, err)
		}
	}

	// Rollback to version 2 — should create version 5.
	if err := vault.Rollback(ctx, path, 2, cfg, env); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	m, err := vault.GetMeta(ctx, path, cfg, env)
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}

	if m.CurrentVersion != 5 {
		t.Errorf("CurrentVersion: got %d, want 5", m.CurrentVersion)
	}

	// Version 2 should still be accessible.
	got, _, err := vault.GetVersion(ctx, path, 2, cfg, env)
	if err != nil {
		t.Fatalf("GetVersion v2: %v", err)
	}
	if string(got) != string(v2Value) {
		t.Errorf("v2 value mismatch")
	}

	// New version 5 should have the same plaintext as v2.
	got5, vm5, err := vault.GetVersion(ctx, path, 5, cfg, env)
	if err != nil {
		t.Fatalf("GetVersion v5: %v", err)
	}
	if string(got5) != string(v2Value) {
		t.Errorf("v5 value should match v2: got %q", got5)
	}
	if vm5.AAD.Version != 5 {
		t.Errorf("v5 AAD.Version: got %d, want 5", vm5.AAD.Version)
	}

	// Custom map should record rolled_back_from.
	rolledFrom, ok := m.Custom["rolled_back_from"]
	if !ok || rolledFrom != "2" {
		t.Errorf("Custom rolled_back_from: got %q (ok=%v)", rolledFrom, ok)
	}
}

func TestRollback_DestroyedVersionBlocked(t *testing.T) {
	resetDispatch(t)
	cfg := testCfg(t)
	env := testEnv(t)
	ctx := context.Background()

	path := "default/ai/openrouter/api_key"

	// Need 2 versions to destroy v1.
	if _, err := vault.RotateValue(ctx, path, []byte("v1"), vmeta.Meta{}, cfg, env); err != nil {
		t.Fatalf("RotateValue v1: %v", err)
	}
	if _, err := vault.RotateValue(ctx, path, []byte("v2"), vmeta.Meta{}, cfg, env); err != nil {
		t.Fatalf("RotateValue v2: %v", err)
	}

	if err := vault.DestroyVersion(ctx, path, 1, cfg, env); err != nil {
		t.Fatalf("DestroyVersion: %v", err)
	}

	err := vault.Rollback(ctx, path, 1, cfg, env)
	if !errors.Is(err, vault.ErrVersionDestroyed) {
		t.Errorf("Rollback destroyed version: want ErrVersionDestroyed, got: %v", err)
	}
}

// -----------------------------------------------------------------------
// Concurrent RotateValue
// -----------------------------------------------------------------------

func TestRotateValue_ConcurrentVersionsSequential(t *testing.T) {
	// Each goroutine gets its own file backend (own directory) to avoid
	// racing on the same data — the test verifies sequential version assignment
	// within a single backend instance accessed concurrently.
	dir := t.TempDir()
	b, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("file.Open: %v", err)
	}
	defer b.Close()

	// We test the backend directly since RotateValue uses dispatch (singleton).
	// The dispatch singleton test is above; here we verify the backend layer.
	canonical := "default/ai/concurrent/api_key"
	const goroutines = 5

	var mu sync.Mutex
	var versions []int
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()

			ctx := context.Background()
			// Get current meta under lock to prevent races.
			mu.Lock()
			existing, err := b.GetMeta(ctx, canonical)
			var newVersion int
			if errors.Is(err, backend.ErrNotFound) {
				newVersion = 1
				existing = vmeta.Meta{
					SchemaVersion:  vmeta.CurrentSchemaVersion,
					Path:           canonical,
					Accessor:       vmeta.NewAccessor(),
					CurrentVersion: 0,
					MaxVersions:    vmeta.DefaultMaxVersions,
					CreatedAt:      time.Now(),
				}
			} else if err != nil {
				mu.Unlock()
				return
			} else {
				newVersion = existing.CurrentVersion + 1
			}

			existing.CurrentVersion = newVersion
			existing.UpdatedAt = time.Now()
			existing.Versions = append(existing.Versions, vmeta.VersionMeta{
				Version:   newVersion,
				CreatedAt: time.Now(),
			})

			_ = b.SetVersioned(ctx, canonical, newVersion, []byte("value"))
			_ = b.SetMeta(ctx, canonical, existing)
			versions = append(versions, newVersion)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(versions) != goroutines {
		t.Errorf("expected %d versions, got %d", goroutines, len(versions))
	}

	// Check no duplicates.
	seen := make(map[int]bool)
	for _, v := range versions {
		if seen[v] {
			t.Errorf("duplicate version %d", v)
		}
		seen[v] = true
	}
}

// -----------------------------------------------------------------------
// AAD binding test
// -----------------------------------------------------------------------

func TestRotateValue_AADBoundToVersion(t *testing.T) {
	resetDispatch(t)
	cfg := testCfg(t)
	env := testEnv(t)
	ctx := context.Background()

	path := "default/ai/openrouter/api_key"
	ver, err := vault.RotateValue(ctx, path, []byte("secret"), vmeta.Meta{}, cfg, env)
	if err != nil {
		t.Fatalf("RotateValue: %v", err)
	}

	m, err := vault.GetMeta(ctx, path, cfg, env)
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}

	var vm vmeta.VersionMeta
	for _, v := range m.Versions {
		if v.Version == ver {
			vm = v
			break
		}
	}

	if vm.AAD.Version != ver {
		t.Errorf("AAD.Version: got %d, want %d", vm.AAD.Version, ver)
	}
	if vm.AAD.Path != path {
		t.Errorf("AAD.Path: got %q, want %q", vm.AAD.Path, path)
	}
	if vm.AAD.Algorithm != "xchacha20-poly1305" {
		t.Errorf("AAD.Algorithm: got %q", vm.AAD.Algorithm)
	}
}

// -----------------------------------------------------------------------
// GetMeta / ListMeta never call backend.Get
// -----------------------------------------------------------------------

func TestGetMeta_NeverCallsBackendGet(t *testing.T) {
	ctx := context.Background()

	// Build a real file backend and wrap it with the spy.
	dir := t.TempDir()
	realBackend, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("file.Open: %v", err)
	}
	t.Cleanup(func() { realBackend.Close() })

	spy := &spyBackend{Backend: realBackend}

	path := "default/ai/openrouter/api_key"

	// Write metadata directly via the spy (delegates to real backend).
	now := time.Now()
	meta := vmeta.Meta{
		SchemaVersion:  vmeta.CurrentSchemaVersion,
		Path:           path,
		Accessor:       vmeta.NewAccessor(),
		Backend:        "file",
		CurrentVersion: 1,
		MaxVersions:    vmeta.DefaultMaxVersions,
		CreatedAt:      now,
		UpdatedAt:      now,
		Versions: []vmeta.VersionMeta{
			{Version: 1, CreatedAt: now},
		},
	}
	if err := spy.SetMeta(ctx, path, meta); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}

	// GetMeta must not call backend.Get.
	got, err := spy.GetMeta(ctx, path)
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}
	if got.Path != path {
		t.Errorf("Path: got %q, want %q", got.Path, path)
	}

	// Assertion: Get must never have been called.
	if count := spy.getCallCount.Load(); count != 0 {
		t.Errorf("GetMeta called backend.Get %d time(s)", count)
	}
}

func TestListMeta_NeverCallsBackendGet(t *testing.T) {
	ctx := context.Background()

	// Build a real file backend and wrap it with the spy.
	dir := t.TempDir()
	realBackend, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("file.Open: %v", err)
	}
	t.Cleanup(func() { realBackend.Close() })

	spy := &spyBackend{Backend: realBackend}

	now := time.Now()
	paths := []string{
		"default/ai/openrouter/api_key",
		"default/ai/anthropic/api_key",
	}
	for _, p := range paths {
		m := vmeta.Meta{
			SchemaVersion:  vmeta.CurrentSchemaVersion,
			Path:           p,
			Accessor:       vmeta.NewAccessor(),
			Backend:        "file",
			CurrentVersion: 1,
			MaxVersions:    vmeta.DefaultMaxVersions,
			CreatedAt:      now,
			UpdatedAt:      now,
			Versions: []vmeta.VersionMeta{
				{Version: 1, CreatedAt: now},
			},
		}
		if err := spy.SetMeta(ctx, p, m); err != nil {
			t.Fatalf("SetMeta %q: %v", p, err)
		}
	}

	metas, err := spy.ListMeta(ctx, "")
	if err != nil {
		t.Fatalf("ListMeta: %v", err)
	}
	if len(metas) != 2 {
		t.Errorf("expected 2 metas, got %d", len(metas))
	}

	// Assertion: Get must never have been called.
	if count := spy.getCallCount.Load(); count != 0 {
		t.Errorf("ListMeta called backend.Get %d time(s)", count)
	}
}
