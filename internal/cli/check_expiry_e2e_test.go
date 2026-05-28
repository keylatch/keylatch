package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/backend/file"
	"github.com/keylatch/keylatch/internal/cli"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/keylatch/keylatch/internal/vault"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
	"github.com/spf13/cobra"
)

func resetDispatchForTest(t *testing.T) {
	t.Helper()
	t.Cleanup(dispatch.ClearCached)
	dispatch.ClearCached()
}

// executeCmd runs a cobra command with the given arguments against the given
// root command. Returns stdout, stderr, and any error.
func executeCmd(t *testing.T, root *cobra.Command, args ...string) (stdout, stderr string) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs(args)
	_ = root.Execute()
	return outBuf.String(), errBuf.String()
}

// setupCheckExpiryFixture creates a vault root with metadata fixtures:
//   - A: expired 2 days ago
//   - B: expires 60 days from now
//   - C: no expiry
//
// Also writes a "canary" value blob that must not appear in check-expiry output.
func setupCheckExpiryFixture(t *testing.T) (dir string, cfgForTest config.Config) {
	t.Helper()
	dir = t.TempDir()

	b, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("file.Open: %v", err)
	}
	defer b.Close()

	ctx := context.Background()
	now := time.Now()

	// A: expired 2 days ago.
	pastTime := now.Add(-48 * time.Hour)
	metaA := vmeta.Meta{
		SchemaVersion:  vmeta.CurrentSchemaVersion,
		Path:           "default/ai/openrouter/api_key",
		Accessor:       vmeta.NewAccessor(),
		Backend:        "file",
		CurrentVersion: 1,
		MaxVersions:    vmeta.DefaultMaxVersions,
		CreatedAt:      now,
		UpdatedAt:      now,
		ExpiresAt:      &pastTime,
		Versions: []vmeta.VersionMeta{
			{Version: 1, CreatedAt: now, AAD: vmeta.AADBinding{
				SchemaVersion: 1, Path: "default/ai/openrouter/api_key", Version: 1,
				Algorithm: "xchacha20-poly1305", BackendID: "file:" + dir, CreatedAt: now,
			}},
		},
	}
	if err := b.SetMeta(ctx, "default/ai/openrouter/api_key", metaA); err != nil {
		t.Fatalf("SetMeta A: %v", err)
	}

	// B: expires 60 days from now.
	futureTime := now.Add(60 * 24 * time.Hour)
	metaB := vmeta.Meta{
		SchemaVersion:  vmeta.CurrentSchemaVersion,
		Path:           "default/ai/anthropic/api_key",
		Accessor:       vmeta.NewAccessor(),
		Backend:        "file",
		CurrentVersion: 1,
		MaxVersions:    vmeta.DefaultMaxVersions,
		CreatedAt:      now,
		UpdatedAt:      now,
		ExpiresAt:      &futureTime,
		Versions: []vmeta.VersionMeta{
			{Version: 1, CreatedAt: now, AAD: vmeta.AADBinding{
				SchemaVersion: 1, Path: "default/ai/anthropic/api_key", Version: 1,
				Algorithm: "xchacha20-poly1305", BackendID: "file:" + dir, CreatedAt: now,
			}},
		},
	}
	if err := b.SetMeta(ctx, "default/ai/anthropic/api_key", metaB); err != nil {
		t.Fatalf("SetMeta B: %v", err)
	}

	// C: no expiry.
	metaC := vmeta.Meta{
		SchemaVersion:  vmeta.CurrentSchemaVersion,
		Path:           "default/storage/dropbox/token",
		Accessor:       vmeta.NewAccessor(),
		Backend:        "file",
		CurrentVersion: 1,
		MaxVersions:    vmeta.DefaultMaxVersions,
		CreatedAt:      now,
		UpdatedAt:      now,
		Versions: []vmeta.VersionMeta{
			{Version: 1, CreatedAt: now, AAD: vmeta.AADBinding{
				SchemaVersion: 1, Path: "default/storage/dropbox/token", Version: 1,
				Algorithm: "xchacha20-poly1305", BackendID: "file:" + dir, CreatedAt: now,
			}},
		},
	}
	if err := b.SetMeta(ctx, "default/storage/dropbox/token", metaC); err != nil {
		t.Fatalf("SetMeta C: %v", err)
	}

	// Write canary value blob directly to values/ directory.
	canaryPath := filepath.Join(dir, "values", "default", "ai", "openrouter", "api_key", "1")
	if err := os.MkdirAll(filepath.Dir(canaryPath), 0o700); err != nil {
		t.Fatalf("mkdir canary: %v", err)
	}
	canary := "KEYLATCH_CANARY_PHASE4_EXPIRY_0xDEADBEEF"
	if err := os.WriteFile(canaryPath, []byte(canary), 0o600); err != nil {
		t.Fatalf("write canary: %v", err)
	}

	return dir, config.Config{Backend: "file", DataDir: dir}
}

func TestCheckExpiry_Days30(t *testing.T) {
	resetDispatchForTest(t)
	dir, _ := setupCheckExpiryFixture(t)

	root := cli.NewRootCommand()
	root.SetArgs([]string{"check-expiry", "--days", "30"})

	var outBuf, errBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)

	// Need to set data dir and keyring path via env.
	t.Setenv("KEYLATCH_DATA_DIR", dir)
	t.Setenv("KEYLATCH_BACKEND", "file")
	testutil.SetupTestKeyring(t) // sets KEYLATCH_AGE_IDENTITY + KEYLATCH_KEYRING_PATH

	root.Execute()
	out := outBuf.String()

	// A (expired) must be listed.
	if !strings.Contains(out, "openrouter") {
		t.Errorf("expected openrouter (expired) in output, got: %s", out)
	}
	// B (60 days) must not be listed at --days 30.
	if strings.Contains(out, "anthropic") {
		t.Errorf("expected anthropic (60 days) not in output, got: %s", out)
	}
}

func TestCheckExpiry_Days90(t *testing.T) {
	resetDispatchForTest(t)
	dir, _ := setupCheckExpiryFixture(t)

	t.Setenv("KEYLATCH_DATA_DIR", dir)
	t.Setenv("KEYLATCH_BACKEND", "file")
	testutil.SetupTestKeyring(t)

	root := cli.NewRootCommand()
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"check-expiry", "--days", "90"})
	root.Execute()

	out := outBuf.String()
	// Both A and B should appear.
	if !strings.Contains(out, "openrouter") {
		t.Errorf("expected openrouter in output: %s", out)
	}
	if !strings.Contains(out, "anthropic") {
		t.Errorf("expected anthropic in output: %s", out)
	}
}

func TestCheckExpiry_JSONOutput(t *testing.T) {
	resetDispatchForTest(t)
	dir, _ := setupCheckExpiryFixture(t)

	t.Setenv("KEYLATCH_DATA_DIR", dir)
	t.Setenv("KEYLATCH_BACKEND", "file")
	testutil.SetupTestKeyring(t)

	root := cli.NewRootCommand()
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"check-expiry", "--json", "--days", "30"})
	root.Execute()

	out := outBuf.String()

	// Must be valid JSON.
	var entries []map[string]interface{}
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		t.Fatalf("JSON parse error: %v\noutput: %s", err, out)
	}

	// Must contain the expired entry.
	found := false
	for _, e := range entries {
		if p, _ := e["path"].(string); strings.Contains(p, "openrouter") {
			found = true
		}
	}
	if !found {
		t.Errorf("expired entry not found in JSON output: %s", out)
	}
}

// TestCheckExpiry_CanaryAbsent verifies S4-1: the canary value is never in output.
func TestCheckExpiry_CanaryAbsent(t *testing.T) {
	resetDispatchForTest(t)
	dir, _ := setupCheckExpiryFixture(t)

	t.Setenv("KEYLATCH_DATA_DIR", dir)
	t.Setenv("KEYLATCH_BACKEND", "file")
	testutil.SetupTestKeyring(t)

	root := cli.NewRootCommand()
	var outBuf, errBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs([]string{"check-expiry", "--days", "90"})
	root.Execute()

	if strings.Contains(outBuf.String(), "KEYLATCH_CANARY_PHASE4_EXPIRY_0xDEADBEEF") {
		t.Error("canary value appeared in check-expiry stdout — S4-1 violated")
	}
	if strings.Contains(errBuf.String(), "KEYLATCH_CANARY_PHASE4_EXPIRY_0xDEADBEEF") {
		t.Error("canary value appeared in check-expiry stderr — S4-1 violated")
	}
}

// TestSetMeta_ValidatesExpiresBeforeIssued tests that the vault rejects
// invalid metadata with ErrExpiresBeforeIssued.
func TestSetMeta_ValidatesExpiresBeforeIssued(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	cfg := config.Config{Backend: "file", DataDir: dir}
	krPath := testutil.SetupTestKeyring(t)
	env := func(k string) string {
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

	resetDispatchForTest(t)

	now := time.Now()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)

	m := vmeta.Meta{
		SchemaVersion:  vmeta.CurrentSchemaVersion,
		Path:           "default/ai/openrouter/api_key",
		Accessor:       vmeta.NewAccessor(),
		CurrentVersion: 1,
		MaxVersions:    5,
		CreatedAt:      now,
		UpdatedAt:      now,
		IssuedAt:       &future, // issued in the future
		ExpiresAt:      &past,   // expires in the past (before issued)
	}

	err := vault.SetMeta(ctx, "default/ai/openrouter/api_key", m, cfg, env)
	if err == nil {
		t.Error("expected validation error for expires before issued")
	}
}
