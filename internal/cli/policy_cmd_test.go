package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/testutil"
)

func runPolicyCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"policy"}, args...))
	err := root.Execute()
	return out.String(), err
}

// With no policy file yet, every policy command must treat the policy as
// the default-deny one instead of failing on the missing file.
func TestPolicyCommandsWithoutPolicyFile(t *testing.T) {
	testutil.ClearLLMSessionEnv(t)
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)
	t.Setenv("KEYLATCH_POLICY_PATH", "")
	t.Setenv("KEYLATCH_GRANTS_PATH", filepath.Join(dir, "grants.json"))

	if out, err := runPolicyCmd(t, "list"); err != nil {
		t.Fatalf("policy list: %v\n%s", err, out)
	}
	out, err := runPolicyCmd(t, "list", "--json")
	if err != nil {
		t.Fatalf("policy list --json: %v\n%s", err, out)
	}
	if strings.TrimSpace(out) != "[]" {
		t.Fatalf("policy list --json = %q, want []", out)
	}
	out, err = runPolicyCmd(t, "check", "--json", "claude-code", "openrouter")
	if err != nil || !strings.Contains(out, `"allow": false`) {
		t.Fatalf("policy check = %q, %v; want a deny decision", out, err)
	}
	_, err = runPolicyCmd(t, "remove", "missing-rule")
	if err == nil || !strings.Contains(err.Error(), `rule "missing-rule" not found`) {
		t.Fatalf("policy remove = %v, want rule not found", err)
	}
	if out, err := runPolicyCmd(t, "allow", "claude-code", "openrouter"); err != nil {
		t.Fatalf("policy allow: %v\n%s", err, out)
	}
	out, err = runPolicyCmd(t, "list", "--json")
	if err != nil || !strings.Contains(out, `"openrouter"`) {
		t.Fatalf("policy list after allow = %q, %v", out, err)
	}
}
