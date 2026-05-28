package cli_test

// S4-8 tests: destroy-version and rollback must be blocked in LLM sessions
// and must not modify the vault when blocked.

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/cli"
	"github.com/keylatch/keylatch/internal/vault"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

// TestDestroyVersion_BlockedInLLMSession verifies S4-8: destroy-version returns
// an error in an LLM session and does NOT destroy any version.
func TestDestroyVersion_BlockedInLLMSession(t *testing.T) {
	dir := t.TempDir()
	dispatch.ClearCached()
	t.Cleanup(dispatch.ClearCached)
	t.Setenv("KEYLATCH_DATA_DIR", dir)
	t.Setenv("KEYLATCH_BACKEND", "file")
	// Inject CLAUDE_CODE=1 so llmcontext.DefaultLookup sees the LLM signal.
	t.Setenv("CLAUDE_CODE", "1")

	ctx := context.Background()
	cfg := newTestConfig(dir)
	env := newTestEnv(t, dir)

	// Set up: create two versions so destroy-version has a valid target.
	path := "default/ai/openrouter/api_key"
	if _, err := vault.RotateValue(ctx, path, []byte("v1"), vmeta.Meta{}, cfg, env); err != nil {
		t.Fatalf("RotateValue v1: %v", err)
	}
	if _, err := vault.RotateValue(ctx, path, []byte("v2"), vmeta.Meta{}, cfg, env); err != nil {
		t.Fatalf("RotateValue v2: %v", err)
	}

	// Run the command.
	root := cli.NewRootCommand()
	var outBuf, errBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs([]string{"destroy-version", path, "1", "--force"})
	err := root.Execute()

	// Must return an error (security block).
	if err == nil {
		t.Error("expected error from destroy-version in LLM session, got nil")
	}
	if !strings.Contains(err.Error(), "security block") {
		t.Errorf("expected 'security block' in error, got: %v", err)
	}

	// Vault must NOT have been modified: v1 must still be accessible.
	_, _, getErr := vault.GetVersion(ctx, path, 1, cfg, env)
	if getErr != nil {
		t.Errorf("S4-8 violated: vault was modified — v1 should still be live, got: %v", getErr)
	}
}

// TestRollback_BlockedInLLMSession verifies S4-8: rollback returns an error in
// an LLM session and does NOT create a new version.
func TestRollback_BlockedInLLMSession(t *testing.T) {
	dir := t.TempDir()
	dispatch.ClearCached()
	t.Cleanup(dispatch.ClearCached)
	t.Setenv("KEYLATCH_DATA_DIR", dir)
	t.Setenv("KEYLATCH_BACKEND", "file")
	// Inject CLAUDE_CODE=1 so llmcontext.DefaultLookup sees the LLM signal.
	t.Setenv("CLAUDE_CODE", "1")

	ctx := context.Background()
	cfg := newTestConfig(dir)
	env := newTestEnv(t, dir)

	// Set up: create two versions.
	path := "default/ai/openrouter/api_key"
	if _, err := vault.RotateValue(ctx, path, []byte("v1"), vmeta.Meta{}, cfg, env); err != nil {
		t.Fatalf("RotateValue v1: %v", err)
	}
	if _, err := vault.RotateValue(ctx, path, []byte("v2"), vmeta.Meta{}, cfg, env); err != nil {
		t.Fatalf("RotateValue v2: %v", err)
	}

	// Run the command.
	root := cli.NewRootCommand()
	var outBuf, errBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs([]string{"rollback", path, "1", "--force"})
	err := root.Execute()

	// Must return an error (security block).
	if err == nil {
		t.Error("expected error from rollback in LLM session, got nil")
	}
	if !strings.Contains(err.Error(), "security block") {
		t.Errorf("expected 'security block' in error, got: %v", err)
	}

	// Vault must NOT have been modified: current version must still be 2.
	m, metaErr := vault.GetMeta(ctx, path, cfg, env)
	if metaErr != nil {
		t.Fatalf("GetMeta: %v", metaErr)
	}
	if m.CurrentVersion != 2 {
		t.Errorf("S4-8 violated: vault was modified — CurrentVersion should be 2, got %d", m.CurrentVersion)
	}
}
