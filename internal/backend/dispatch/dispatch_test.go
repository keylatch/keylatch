package dispatch_test

import (
	"context"
	"errors"
	"runtime"
	"strings"
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
	cfg.Backend = "file"
	cfg.DataDir = t.TempDir()
	return cfg
}

func TestSelect_NoImplicitDefault(t *testing.T) {
	dispatch.ClearCached()
	defer dispatch.ClearCached()

	cfg := tempDirConfig(t)
	cfg.Backend = ""

	_, err := dispatch.Select(context.Background(), cfg, fakeEnv(nil))
	if !errors.Is(err, dispatch.ErrNoBackend) {
		t.Fatalf("no backend configured: got %v, want ErrNoBackend", err)
	}
	for _, id := range backend.SupportedManagers() {
		if !strings.Contains(err.Error(), id) {
			t.Errorf("error %q does not name supported manager %q", err, id)
		}
	}
}

func TestSelect_UnsupportedBackendNeedsOptIn(t *testing.T) {
	dispatch.ClearCached()
	defer dispatch.ClearCached()
	t.Setenv(backend.AllowUnsupportedEnv, "")

	cfg := tempDirConfig(t)
	_, err := dispatch.Select(context.Background(), cfg, fakeEnv(nil))
	if !errors.Is(err, backend.ErrUnsupportedBackend) {
		t.Fatalf("file without opt-in: got %v, want ErrUnsupportedBackend", err)
	}
	for _, want := range []string{`"file"`, "not supported", "bw, op", backend.AllowUnsupportedEnv} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestSelect_OptInNamesOnlyThatBackend(t *testing.T) {
	dispatch.ClearCached()
	defer dispatch.ClearCached()
	t.Setenv(backend.AllowUnsupportedEnv, "keychain")

	cfg := tempDirConfig(t)
	_, err := dispatch.Select(context.Background(), cfg, fakeEnv(nil))
	if !errors.Is(err, backend.ErrUnsupportedBackend) {
		t.Fatalf("opt-in for keychain must not open file: got %v", err)
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
	cfg.Backend = "nonesuch"

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
	// Hermetic: a real CLI installed on the host would otherwise make the backend available.
	t.Setenv("PATH", t.TempDir())
	t.Setenv("KEYLATCH_OP_BIN", "")
	dispatch.ClearCached()
	defer dispatch.ClearCached()
	t.Setenv("PATH", t.TempDir())

	cfg := tempDirConfig(t)
	cfg.Backend = "op"

	_, err := dispatch.Select(context.Background(), cfg, nil)
	if !errors.Is(err, backend.ErrUnavailable) {
		t.Errorf("op backend: got %v, want ErrUnavailable", err)
	}
}

func TestSelect_BWUnavailable(t *testing.T) {
	// Hermetic: a real CLI installed on the host would otherwise make the backend available.
	t.Setenv("PATH", t.TempDir())
	t.Setenv("KEYLATCH_BW_BIN", "")
	dispatch.ClearCached()
	defer dispatch.ClearCached()
	t.Setenv("PATH", t.TempDir())

	cfg := tempDirConfig(t)
	cfg.Backend = "bw"

	_, err := dispatch.Select(context.Background(), cfg, nil)
	if !errors.Is(err, backend.ErrUnavailable) {
		t.Errorf("bw backend: got %v, want ErrUnavailable", err)
	}
}

func TestSelect_KeychainIsNeverOpened(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("this test is for non-darwin platforms only")
	}

	dispatch.ClearCached()
	defer dispatch.ClearCached()

	cfg := tempDirConfig(t)
	cfg.Backend = "keychain"

	_, err := dispatch.Select(context.Background(), cfg, nil)
	if !errors.Is(err, backend.ErrUnsupportedBackend) {
		t.Errorf("keychain: got %v, want ErrUnsupportedBackend", err)
	}
}

func TestSelect_OptInCannotEnableUnmarkedBackends(t *testing.T) {
	for _, id := range []string{"keeper", "proton-pass", "op-connect", "keychain"} {
		t.Run(id, func(t *testing.T) {
			dispatch.ClearCached()
			defer dispatch.ClearCached()
			t.Setenv(backend.AllowUnsupportedEnv, "keeper,proton-pass,op-connect,keychain,"+id)

			cfg := tempDirConfig(t)
			cfg.Backend = id
			_, err := dispatch.Open(context.Background(), cfg, fakeEnv(nil))
			if !errors.Is(err, backend.ErrUnsupportedBackend) {
				t.Fatalf("%s with the opt-in set: got %v, want ErrUnsupportedBackend", id, err)
			}
			if strings.Contains(err.Error(), backend.AllowUnsupportedEnv) {
				t.Errorf("error %q must not suggest the opt-in", err)
			}
		})
	}
}
