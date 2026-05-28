package dispatch_test

import (
	"context"
	"errors"
	"runtime"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/testutil"
)

func fakeEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func tempDirConfig(t *testing.T) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	return cfg
}

func TestSelect_Default(t *testing.T) {
	dispatch.ClearCached()
	defer dispatch.ClearCached()

	krPath := testutil.SetupTestKeyring(t)
	cfg := tempDirConfig(t)
	cfg.Backend = ""
	env := fakeEnv(map[string]string{"KEYLATCH_KEYRING_PATH": krPath})

	b, err := dispatch.Select(context.Background(), cfg, env)
	if err != nil {
		t.Fatalf("Select default: %v", err)
	}
	if b.Name() != "file" {
		t.Errorf("default backend: got %q, want file", b.Name())
	}
}

func TestSelect_EnvOverridesDefault(t *testing.T) {
	dispatch.ClearCached()
	defer dispatch.ClearCached()

	krPath := testutil.SetupTestKeyring(t)
	cfg := tempDirConfig(t)
	cfg.Backend = ""
	env := fakeEnv(map[string]string{
		"KEYLATCH_BACKEND":      "file",
		"KEYLATCH_DATA_DIR":     t.TempDir(),
		"KEYLATCH_KEYRING_PATH": krPath,
	})

	b, err := dispatch.Select(context.Background(), cfg, env)
	if err != nil {
		t.Fatalf("Select env: %v", err)
	}
	if b.Name() != "file" {
		t.Errorf("env backend: got %q, want file", b.Name())
	}
}

func TestSelect_ConfigOverridesEnv(t *testing.T) {
	dispatch.ClearCached()
	defer dispatch.ClearCached()

	krPath := testutil.SetupTestKeyring(t)
	cfg := tempDirConfig(t)
	cfg.Backend = "file" // config wins
	env := fakeEnv(map[string]string{
		// Even if KEYLATCH_BACKEND were keychain, config should win.
		"KEYLATCH_BACKEND":      "file",
		"KEYLATCH_KEYRING_PATH": krPath,
	})

	b, err := dispatch.Select(context.Background(), cfg, env)
	if err != nil {
		t.Fatalf("Select config: %v", err)
	}
	if b.Name() != "file" {
		t.Errorf("config backend: got %q, want file", b.Name())
	}
}

func TestSelect_UnknownBackend(t *testing.T) {
	dispatch.ClearCached()
	defer dispatch.ClearCached()

	cfg := tempDirConfig(t)
	cfg.Backend = "sops"

	_, err := dispatch.Select(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("unknown backend: expected error, got nil")
	}
	var unknownErr dispatch.ErrUnknownBackend
	if !errors.As(err, &unknownErr) {
		t.Errorf("unknown backend: got %T (%v), want ErrUnknownBackend", err, err)
	}
}

func TestSelect_Reset(t *testing.T) {
	dispatch.ClearCached()
	defer dispatch.ClearCached()

	krPath := testutil.SetupTestKeyring(t)
	cfg := tempDirConfig(t)
	env := fakeEnv(map[string]string{"KEYLATCH_KEYRING_PATH": krPath})

	b1, err := dispatch.Select(context.Background(), cfg, env)
	if err != nil {
		t.Fatalf("first Select: %v", err)
	}

	// Second call returns same cached instance.
	b2, err := dispatch.Select(context.Background(), cfg, env)
	if err != nil {
		t.Fatalf("second Select: %v", err)
	}
	if b1 != b2 {
		t.Error("second Select: expected same cached instance")
	}

	// After Reset, a new instance is returned.
	dispatch.ClearCached()
	cfg2 := tempDirConfig(t)
	b3, err := dispatch.Select(context.Background(), cfg2, env)
	if err != nil {
		t.Fatalf("third Select after Reset: %v", err)
	}
	if b3 == b1 {
		t.Error("after Reset: expected new instance, got same pointer")
	}
}

func TestSelect_OPUnavailable(t *testing.T) {
	dispatch.ClearCached()
	defer dispatch.ClearCached()

	cfg := tempDirConfig(t)
	cfg.Backend = "op"

	_, err := dispatch.Select(context.Background(), cfg, nil)
	if !errors.Is(err, backend.ErrUnavailable) {
		t.Errorf("op backend: got %v, want ErrUnavailable", err)
	}
}

func TestSelect_BWUnavailable(t *testing.T) {
	dispatch.ClearCached()
	defer dispatch.ClearCached()

	cfg := tempDirConfig(t)
	cfg.Backend = "bw"

	_, err := dispatch.Select(context.Background(), cfg, nil)
	if !errors.Is(err, backend.ErrUnavailable) {
		t.Errorf("bw backend: got %v, want ErrUnavailable", err)
	}
}

func TestSelect_KeychainOnNonDarwin(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("this test is for non-darwin platforms only")
	}

	dispatch.ClearCached()
	defer dispatch.ClearCached()

	cfg := tempDirConfig(t)
	cfg.Backend = "keychain"

	_, err := dispatch.Select(context.Background(), cfg, nil)
	if !errors.Is(err, backend.ErrUnavailable) {
		t.Errorf("keychain on non-darwin: got %v, want ErrUnavailable", err)
	}
}
