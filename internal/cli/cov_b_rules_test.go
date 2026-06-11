package cli

// cov_b_rules_test.go — Agent B coverage for rules_cmd.go.
// Tests for rules list/create/delete commands and load/save helpers.
// Hermetic: all filesystem access is redirected via KEYLATCH_CONFIG_DIR.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupRulesDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)
	return dir
}

func envForRulesDir(dir string) func(string) string {
	return func(key string) string {
		if key == "KEYLATCH_CONFIG_DIR" {
			return dir
		}
		return os.Getenv(key)
	}
}

func TestRulesList_Empty(t *testing.T) {
	dir := setupRulesDir(t)

	rules, err := loadGatewayRules(envForRulesDir(dir))
	if err != nil {
		t.Fatalf("loadGatewayRules: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected empty rules, got: %d", len(rules))
	}
}

func TestRulesList_Command_Empty(t *testing.T) {
	setupRulesDir(t)

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"rules", "list"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out.String(), "ID") {
		t.Errorf("expected header in output, got: %s", out.String())
	}
}

func TestRulesCreate_Block(t *testing.T) {
	setupRulesDir(t)

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"rules", "create",
		"--provider", "openai",
		"--action", "completions",
		"--block",
	})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out.String(), "block") {
		t.Errorf("expected 'block' in output, got: %s", out.String())
	}
	if !strings.Contains(out.String(), "openai") {
		t.Errorf("expected 'openai' in output, got: %s", out.String())
	}
}

func TestRulesCreate_RequireApproval(t *testing.T) {
	setupRulesDir(t)

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"rules", "create",
		"--provider", "anthropic",
		"--action", "messages",
		"--require-approval",
	})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out.String(), "require-approval") {
		t.Errorf("expected 'require-approval' in output, got: %s", out.String())
	}
}

func TestRulesCreate_RateLimit(t *testing.T) {
	setupRulesDir(t)

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"rules", "create",
		"--provider", "cohere",
		"--action", "generate",
		"--rate-limit", "10/1m",
	})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out.String(), "rate-limit") {
		t.Errorf("expected 'rate-limit' in output, got: %s", out.String())
	}
}

func TestRulesCreate_MissingProvider(t *testing.T) {
	setupRulesDir(t)

	root := NewRootCommand()
	root.SetOut(bytes.NewBuffer(nil))
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"rules", "create", "--action", "completions", "--block"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when --provider is missing")
	}
	if !strings.Contains(err.Error(), "--provider") {
		t.Errorf("expected '--provider' in error, got: %v", err)
	}
}

func TestRulesCreate_MissingAction(t *testing.T) {
	setupRulesDir(t)

	root := NewRootCommand()
	root.SetOut(bytes.NewBuffer(nil))
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"rules", "create", "--provider", "openai", "--block"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when --action is missing")
	}
	if !strings.Contains(err.Error(), "--action") {
		t.Errorf("expected '--action' in error, got: %v", err)
	}
}

func TestRulesCreate_MissingKind(t *testing.T) {
	setupRulesDir(t)

	root := NewRootCommand()
	root.SetOut(bytes.NewBuffer(nil))
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"rules", "create", "--provider", "openai", "--action", "completions"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when no --block/--require-approval/--rate-limit specified")
	}
}

func TestRulesDelete_DeletesRule(t *testing.T) {
	dir := setupRulesDir(t)
	env := envForRulesDir(dir)

	// Create a rule directly.
	rule := GatewayRule{
		ID:       "rule_test001",
		Provider: "openai",
		Action:   "completions",
		Kind:     "block",
	}
	if err := saveGatewayRules(env, []GatewayRule{rule}); err != nil {
		t.Fatalf("saveGatewayRules: %v", err)
	}

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"rules", "delete", "rule_test001"})

	if err := root.Execute(); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if !strings.Contains(out.String(), "rule_test001") {
		t.Errorf("expected rule ID in output, got: %s", out.String())
	}

	// Verify gone.
	rules, err := loadGatewayRules(env)
	if err != nil {
		t.Fatalf("loadGatewayRules: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules after delete, got: %d", len(rules))
	}
}

func TestRulesDelete_NotFound(t *testing.T) {
	setupRulesDir(t)

	root := NewRootCommand()
	root.SetOut(bytes.NewBuffer(nil))
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"rules", "delete", "nonexistent"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for missing rule")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

func TestRulesList_JSON(t *testing.T) {
	dir := setupRulesDir(t)
	env := envForRulesDir(dir)

	rules := []GatewayRule{
		{ID: "rule_abc123", Provider: "openai", Action: "completions", Kind: "block"},
		{ID: "rule_def456", Provider: "anthropic", Action: "messages", Kind: "require-approval"},
	}
	if err := saveGatewayRules(env, rules); err != nil {
		t.Fatalf("saveGatewayRules: %v", err)
	}

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"rules", "list", "--json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("list --json: %v", err)
	}

	var arr []GatewayRule
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &arr); err != nil {
		t.Fatalf("JSON parse: %v — output: %s", err, out.String())
	}
	if len(arr) != 2 {
		t.Errorf("expected 2 rules, got: %d", len(arr))
	}
}

func TestLoadGatewayRules_InvalidJSON(t *testing.T) {
	dir := setupRulesDir(t)
	env := envForRulesDir(dir)

	rulesPath := filepath.Join(dir, "gateway-rules.json")
	if err := os.WriteFile(rulesPath, []byte("{not valid"), 0o600); err != nil {
		t.Fatalf("write bad json: %v", err)
	}

	_, err := loadGatewayRules(env)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestNewGatewayRuleID_Format(t *testing.T) {
	id, err := newGatewayRuleID()
	if err != nil {
		t.Fatalf("newGatewayRuleID: %v", err)
	}
	if !strings.HasPrefix(id, "rule_") {
		t.Errorf("expected id to start with 'rule_', got: %s", id)
	}
	// rule_ + 16 hex chars = 21 chars total
	if len(id) != 21 {
		t.Errorf("expected id length 21, got: %d (%s)", len(id), id)
	}
}

func TestNewGatewayRuleID_Unique(t *testing.T) {
	ids := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		id, err := newGatewayRuleID()
		if err != nil {
			t.Fatalf("newGatewayRuleID: %v", err)
		}
		if _, dup := ids[id]; dup {
			t.Errorf("duplicate ID generated: %s", id)
		}
		ids[id] = struct{}{}
	}
}

func TestSaveGatewayRules_AtomicWrite(t *testing.T) {
	dir := setupRulesDir(t)
	env := envForRulesDir(dir)

	rules := []GatewayRule{{ID: "rule_atomic", Provider: "test", Action: "test", Kind: "block"}}
	if err := saveGatewayRules(env, rules); err != nil {
		t.Fatalf("saveGatewayRules: %v", err)
	}

	// Verify no .tmp file left behind.
	rulesPath := filepath.Join(dir, "gateway-rules.json")
	tmpPath := rulesPath + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("expected .tmp file to be cleaned up after atomic write")
	}
}

func TestRulesList_TableTruncatesLongID(t *testing.T) {
	dir := setupRulesDir(t)
	env := envForRulesDir(dir)

	// Use a long ID to trigger truncation in table output.
	rules := []GatewayRule{
		{ID: "rule_verylongidentifier999", Provider: "openai", Action: "completions", Kind: "block"},
	}
	if err := saveGatewayRules(env, rules); err != nil {
		t.Fatalf("saveGatewayRules: %v", err)
	}

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"rules", "list"})

	if err := root.Execute(); err != nil {
		t.Fatalf("list: %v", err)
	}

	// Output should contain "..." (truncation indicator) since ID > 12 chars.
	if !strings.Contains(out.String(), "...") {
		t.Errorf("expected truncated ID with '...', got: %s", out.String())
	}
}
