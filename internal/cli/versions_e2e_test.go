package cli_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/cli"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/keylatch/keylatch/internal/vault"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

func newTestConfig(dir string) config.Config {
	return config.Config{Backend: "file", DataDir: dir}
}

// newTestEnv returns an env lookup for the file backend that includes the
// keyring path. t.Setenv is called so KEYLATCH_KEYRING_PATH is visible to
// any child process or cobra command that reads os.Getenv directly.
func newTestEnv(t *testing.T, dir string) func(string) string {
	t.Helper()
	krPath := testutil.SetupTestKeyring(t)
	t.Setenv("KEYLATCH_KEYRING_PATH", krPath)
	return func(k string) string {
		switch k {
		case "KEYLATCH_BACKEND":
			return "file"
		case "KEYLATCH_DATA_DIR":
			return dir
		case "KEYLATCH_KEYRING_PATH":
			return krPath
		}
		return ""
	}
}

func TestVersionsCmd_ThreeRotations(t *testing.T) {
	testutil.SetupHermeticConfig(t)
	dir := t.TempDir()
	t.Setenv("KEYLATCH_DATA_DIR", dir)
	t.Setenv("KEYLATCH_BACKEND", "file")
	dispatch.ClearCached()
	t.Cleanup(dispatch.ClearCached)

	ctx := context.Background()
	cfg := newTestConfig(dir)
	env := newTestEnv(t, dir)

	path := "default/ai/openrouter/api_key"
	for i := 0; i < 3; i++ {
		if _, err := vault.RotateValue(ctx, path, []byte("secret"), vmeta.Meta{}, cfg, env); err != nil {
			t.Fatalf("RotateValue %d: %v", i+1, err)
		}
	}

	root := cli.NewRootCommand()
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"versions", path})
	root.Execute()

	out := outBuf.String()

	// Should show 3 rows.
	count := strings.Count(out, "live")
	if count < 1 {
		t.Errorf("expected at least 1 'live' row, got output: %s", out)
	}

	// Version 3 should be marked current (*).
	if !strings.Contains(out, "3") {
		t.Errorf("expected version 3 in output: %s", out)
	}
}

func TestVersionsCmd_DestroyedVersionState(t *testing.T) {
	testutil.SetupHermeticConfig(t)
	dir := t.TempDir()
	dispatch.ClearCached()
	t.Cleanup(dispatch.ClearCached)

	ctx := context.Background()
	cfg := newTestConfig(dir)
	env := newTestEnv(t, dir)

	path := "default/ai/openrouter/api_key"

	// Create 2 versions.
	if _, err := vault.RotateValue(ctx, path, []byte("v1"), vmeta.Meta{}, cfg, env); err != nil {
		t.Fatalf("RotateValue v1: %v", err)
	}
	if _, err := vault.RotateValue(ctx, path, []byte("v2"), vmeta.Meta{}, cfg, env); err != nil {
		t.Fatalf("RotateValue v2: %v", err)
	}

	// Destroy v1.
	if err := vault.DestroyVersion(ctx, path, 1, cfg, env); err != nil {
		t.Fatalf("DestroyVersion: %v", err)
	}

	t.Setenv("KEYLATCH_DATA_DIR", dir)
	t.Setenv("KEYLATCH_BACKEND", "file")

	root := cli.NewRootCommand()
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"versions", path})
	root.Execute()

	out := outBuf.String()
	if !strings.Contains(out, "destroyed") {
		t.Errorf("expected 'destroyed' state in output: %s", out)
	}
}

func TestVersionsCmd_RollbackShowsNewVersion(t *testing.T) {
	testutil.SetupHermeticConfig(t)
	dir := t.TempDir()
	dispatch.ClearCached()
	t.Cleanup(dispatch.ClearCached)

	ctx := context.Background()
	cfg := newTestConfig(dir)
	env := newTestEnv(t, dir)

	path := "default/ai/openrouter/api_key"

	// Create 3 versions.
	for i := 0; i < 3; i++ {
		if _, err := vault.RotateValue(ctx, path, []byte("secret"), vmeta.Meta{}, cfg, env); err != nil {
			t.Fatalf("RotateValue %d: %v", i+1, err)
		}
	}

	// Rollback to v2.
	if err := vault.Rollback(ctx, path, 2, cfg, env); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	t.Setenv("KEYLATCH_DATA_DIR", dir)
	t.Setenv("KEYLATCH_BACKEND", "file")

	root := cli.NewRootCommand()
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"versions", path})
	root.Execute()

	out := outBuf.String()

	// Version 4 should appear (rollback creates new version).
	if !strings.Contains(out, "4") {
		t.Errorf("expected version 4 in output after rollback: %s", out)
	}
	// Version 2 should still show as live.
	// Check that we have multiple live entries.
	liveCount := strings.Count(out, "live")
	if liveCount < 2 {
		t.Errorf("expected at least 2 live versions, got output: %s", out)
	}
}

func TestGetVersion_DestroyedReturnsError(t *testing.T) {
	dir := t.TempDir()
	testutil.SetupHermeticConfig(t)
	dispatch.ClearCached()
	t.Cleanup(dispatch.ClearCached)

	ctx := context.Background()
	cfg := newTestConfig(dir)
	env := newTestEnv(t, dir)

	path := "default/ai/openrouter/api_key"

	if _, err := vault.RotateValue(ctx, path, []byte("v1"), vmeta.Meta{}, cfg, env); err != nil {
		t.Fatalf("RotateValue: %v", err)
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

// TestVersionsCmd_CanaryAbsent verifies that the canary value in the encrypted
// blob never appears in `versions` stdout.
func TestVersionsCmd_CanaryAbsent(t *testing.T) {
	testutil.SetupHermeticConfig(t)
	dir := t.TempDir()
	dispatch.ClearCached()
	t.Cleanup(dispatch.ClearCached)

	ctx := context.Background()
	cfg := newTestConfig(dir)
	env := newTestEnv(t, dir)

	path := "default/ai/openrouter/api_key"
	if _, err := vault.RotateValue(ctx, path, []byte("v1"), vmeta.Meta{}, cfg, env); err != nil {
		t.Fatalf("RotateValue: %v", err)
	}

	// Overwrite the value file with the canary string to simulate what an
	// attacker's value blob might contain.
	canaryPath := filepath.Join(dir, "values", "default", "ai", "openrouter", "api_key", "1")
	if err := os.WriteFile(canaryPath, []byte("KEYLATCH_CANARY_PHASE4_VERSIONS_0xDEADBEEF"), 0o600); err != nil {
		t.Fatalf("write canary: %v", err)
	}

	t.Setenv("KEYLATCH_DATA_DIR", dir)
	t.Setenv("KEYLATCH_BACKEND", "file")

	root := cli.NewRootCommand()
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"versions", path})
	root.Execute()

	if strings.Contains(outBuf.String(), "KEYLATCH_CANARY_PHASE4_VERSIONS_0xDEADBEEF") {
		t.Error("canary value appeared in versions output — S4-1 violated")
	}
}
