package cli

// cov_b_share_rollback_test.go — Agent B coverage for share_cmd.go and rollback_cmd.go.
// Tests for share command (non-network paths) and rollback flag/arg validation.
// Hermetic: no network, no OS keychain.

import (
	"bytes"
	"strings"
	"testing"
)

// --- share_cmd.go ---

func TestShareCmd_NoPublicFlag_PrintsNotImplemented(t *testing.T) {
	root := NewRootCommand()
	var errBuf bytes.Buffer
	root.SetOut(bytes.NewBuffer(nil))
	root.SetErr(&errBuf)
	root.SetArgs([]string{"share", "some-receipt-id"})

	if err := root.Execute(); err != nil {
		t.Fatalf("share without --public: unexpected error: %v", err)
	}

	if !strings.Contains(errBuf.String(), "not yet implemented") {
		t.Errorf("expected 'not yet implemented' in stderr, got: %s", errBuf.String())
	}
}

func TestShareCmd_RequiresReceiptID(t *testing.T) {
	root := NewRootCommand()
	root.SetOut(bytes.NewBuffer(nil))
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"share"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when receipt-id is missing")
	}
}

func TestShareCmd_Registered(t *testing.T) {
	root := NewRootCommand()
	shareCmd, _, err := root.Find([]string{"share"})
	if err != nil || shareCmd == nil {
		t.Fatal("expected 'share' command to be registered")
	}
}

// --- rollback_cmd.go ---

func TestRollbackCmd_Registered(t *testing.T) {
	root := NewRootCommand()
	cmd, _, err := root.Find([]string{"rollback"})
	if err != nil || cmd == nil {
		t.Fatal("expected 'rollback' command to be registered")
	}
}

func TestRollbackCmd_RequiresTwoArgs(t *testing.T) {
	root := NewRootCommand()
	root.SetOut(bytes.NewBuffer(nil))
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"rollback", "only-one-arg"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when version argument is missing")
	}
}

func TestRollbackCmd_RequiresIntVersion(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)
	t.Setenv("KEYLATCH_DATA_DIR", dir)
	t.Setenv("KEYLATCH_BACKEND", "file")

	root := NewRootCommand()
	root.SetOut(bytes.NewBuffer(nil))
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"rollback", "--force", "default/ai/key", "notanint"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for non-integer version")
	}
	if !strings.Contains(err.Error(), "version must be an integer") {
		t.Errorf("expected 'version must be an integer' in error, got: %v", err)
	}
}

func TestRollbackCmd_HasForceFlag(t *testing.T) {
	root := NewRootCommand()
	cmd, _, err := root.Find([]string{"rollback"})
	if err != nil || cmd == nil {
		t.Fatal("expected 'rollback' command to be registered")
	}
	forceFlag := cmd.Flags().Lookup("force")
	if forceFlag == nil {
		t.Error("expected --force flag on rollback command")
	}
}

func TestRollbackCmd_BlockedInLLMSession(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)
	t.Setenv("KEYLATCH_DATA_DIR", dir)
	t.Setenv("KEYLATCH_BACKEND", "file")

	// Simulate an LLM session by setting the Claude Code env var.
	t.Setenv("CLAUDE_CODE", "1")

	root := NewRootCommand()
	root.SetOut(bytes.NewBuffer(nil))
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"rollback", "--force", "default/ai/key", "1"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error: rollback should be blocked in LLM session")
	}
	if !strings.Contains(err.Error(), "security block") && !strings.Contains(err.Error(), "LLM") {
		t.Errorf("expected 'security block' or 'LLM' in error, got: %v", err)
	}
}
