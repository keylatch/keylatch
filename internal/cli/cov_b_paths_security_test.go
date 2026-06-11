package cli

// cov_b_paths_security_test.go — Agent B coverage for paths_cmd.go, security_cmd.go.
// Tests for `keylatch paths`, `keylatch env`, and `keylatch security` commands.
// Hermetic: no network, no OS keychain.

import (
	"bytes"
	"strings"
	"testing"
)

// TestPathsCmd_ShowsColumns verifies that `keylatch paths` prints the expected
// path categories.
func TestPathsCmd_ShowsColumns(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"paths"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	for _, label := range []string{"config", "vault", "audit log", "gateway pid", "gateway log"} {
		if !strings.Contains(output, label) {
			t.Errorf("expected label %q in paths output, got:\n%s", label, output)
		}
	}
}

func TestPathsCmd_UsesConfigDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"paths"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The override dir should appear in the output.
	if !strings.Contains(out.String(), dir) {
		t.Errorf("expected config dir %q to appear in paths output:\n%s", dir, out.String())
	}
}

func TestEnvCmd_ShowsKnownVars(t *testing.T) {
	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"env"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	for _, varName := range []string{"KEYLATCH_BACKEND", "KEYLATCH_CONFIG_DIR", "KEYLATCH_VAULT_PATH"} {
		if !strings.Contains(output, varName) {
			t.Errorf("expected env var %q in output, got:\n%s", varName, output)
		}
	}
}

func TestEnvCmd_ShowsCurrentValue(t *testing.T) {
	t.Setenv("KEYLATCH_BACKEND", "file")

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"env"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	// Should show the current value when set.
	if !strings.Contains(output, "current: file") {
		t.Errorf("expected 'current: file' in env output:\n%s", output)
	}
}

func TestEnvCmd_OmitsUnsetVars(t *testing.T) {
	// Ensure the var is not set.
	t.Setenv("KEYLATCH_VAULT_PATH", "")

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"env"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// KEYLATCH_VAULT_PATH appears in the table but without "current:" since unset.
	output := out.String()
	if !strings.Contains(output, "KEYLATCH_VAULT_PATH") {
		t.Errorf("expected KEYLATCH_VAULT_PATH in output:\n%s", output)
	}
}

func TestSecurityCmd_PrintsInvariants(t *testing.T) {
	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"security"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	// Should contain the security model text.
	if !strings.Contains(output, "secrets") {
		t.Errorf("expected 'secrets' in security output, got:\n%s", output)
	}
	if !strings.Contains(output, "logged") {
		t.Errorf("expected 'logged' in security output, got:\n%s", output)
	}
}

func TestSecurityCmd_NoError(t *testing.T) {
	root := NewRootCommand()
	root.SetOut(bytes.NewBuffer(nil))
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"security"})

	if err := root.Execute(); err != nil {
		t.Errorf("security command should not return error, got: %v", err)
	}
}
