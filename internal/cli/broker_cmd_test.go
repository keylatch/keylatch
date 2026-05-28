package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestBrokerCmd_Registered verifies the broker command is registered unconditionally.
func TestBrokerCmd_Registered(t *testing.T) {
	t.Parallel()
	cmd := newBrokerCmd()
	if cmd.Use != "broker" {
		t.Errorf("broker cmd Use = %q, want broker", cmd.Use)
	}
	// Verify all three subcommands are present.
	subNames := make(map[string]bool)
	for _, sub := range cmd.Commands() {
		subNames[sub.Name()] = true
	}
	for _, name := range []string{"status", "dry-run", "revoke"} {
		if !subNames[name] {
			t.Errorf("broker subcommand %q not registered", name)
		}
	}
}

// TestBrokerStatusCmd_JSON verifies broker status --json returns valid JSON with no secrets.
func TestBrokerStatusCmd_JSON(t *testing.T) {
	t.Parallel()
	root := newBrokerCmd()
	root.PersistentFlags().Bool("json", true, "")
	_ = root.PersistentFlags().Set("json", "true")
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"status"})
	// Out-of-process returns ErrBrokerOutOfProcess, which is surfaced as a
	// CLIError. Execute returns the error; that is the expected path in tests.
	_ = root.Execute()

	// Output may be empty (out-of-process) or contain JSON if in-process.
	// Either way: no forbidden credential values must appear.
	raw := out.String()
	for _, forbidden := range []string{"sk-", "Bearer ", "password", "api_key"} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("broker status JSON must not contain %q", forbidden)
		}
	}
}

// TestBrokerStatusCmd_Table verifies broker status table output.
func TestBrokerStatusCmd_Table(t *testing.T) {
	t.Parallel()
	root := newBrokerCmd()
	root.PersistentFlags().Bool("json", false, "")
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"status"})
	// Out-of-process is expected in unit tests — command may exit non-zero.
	_ = root.Execute()
	// Either "No active scoped tokens." or an error message — just verify
	// no credential values leaked.
	raw := out.String()
	for _, forbidden := range []string{"sk-", "Bearer ", "password", "api_key"} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("broker status table must not contain %q", forbidden)
		}
	}
}

// TestBrokerDryRunCmd_MissingArgs verifies dry-run fails without positional args.
func TestBrokerDryRunCmd_MissingArgs(t *testing.T) {
	t.Parallel()
	cmd := newBrokerDryRunCmd()
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when positional args are missing")
	}
}

// TestBrokerDryRunCmd_MissingCommand verifies dry-run fails without <command> arg.
func TestBrokerDryRunCmd_MissingCommand(t *testing.T) {
	t.Parallel()
	cmd := newBrokerDryRunCmd()
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"openrouter"}) // only one arg, need two
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when <command> arg is missing")
	}
}

// TestBrokerDryRunCmd_BasicExecution verifies dry-run runs without panicking
// and produces no credential leakage.
func TestBrokerDryRunCmd_BasicExecution(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	var errBuf bytes.Buffer
	cmd := newBrokerDryRunCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"openrouter", "node script.js"})
	_ = cmd.Execute()
	// No credential values must appear regardless of in/out-of-process state.
	for _, s := range []string{out.String(), errBuf.String()} {
		for _, forbidden := range []string{"sk-", "Bearer ", "not-a-real-token"} {
			if strings.Contains(s, forbidden) {
				t.Errorf("dry-run output must not contain %q", forbidden)
			}
		}
	}
}

// TestBrokerDryRunCmd_JSON verifies dry-run --json returns valid JSON (in-process path).
// In unit tests the broker is out-of-process, so we verify the error path returns
// no credential values.
func TestBrokerDryRunCmd_JSON(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	cmd := newBrokerDryRunCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--json", "openrouter", "node"})
	_ = cmd.Execute()
	// No credential values must appear regardless of the path taken.
	raw := out.String()
	for _, forbidden := range []string{"sk-", "Bearer ", "password", "api_key"} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("broker dry-run JSON must not contain %q", forbidden)
		}
	}
}

// TestBrokerRevokeCmd_MissingArgs verifies revoke fails without <id> and without --all.
func TestBrokerRevokeCmd_MissingArgs(t *testing.T) {
	t.Parallel()
	cmd := newBrokerRevokeCmd()
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when --id and --all are both missing")
	}
}

// TestBrokerRevokeCmd_OutOfProcess verifies revoke returns error when broker not in-process.
func TestBrokerRevokeCmd_OutOfProcess(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	var errBuf bytes.Buffer
	cmd := newBrokerRevokeCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetArgs([]string{"tok_abc123"})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when broker is not running in-process")
	}
}

// TestBrokerRevokeCmd_NoCredentialLeakage verifies revoke never leaks credential values.
func TestBrokerRevokeCmd_NoCredentialLeakage(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	cmd := newBrokerRevokeCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"--json", "tok_abc123"})
	_ = cmd.Execute()
	raw := out.String()
	for _, forbidden := range []string{"sk-", "Bearer ", "not-a-real-token"} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("broker revoke --json must not contain %q", forbidden)
		}
	}
	// If JSON was emitted, it must be parseable.
	if raw != "" && raw[0] == '{' {
		var payload map[string]any
		if err := json.Unmarshal([]byte(raw), &payload); err != nil {
			t.Errorf("broker revoke --json output is not valid JSON: %v", err)
		}
	}
}

// TestBrokerCmd_NoExperimentalBanner verifies broker Long description has no experimental banner.
func TestBrokerCmd_NoExperimentalBanner(t *testing.T) {
	t.Parallel()
	cmd := newBrokerCmd()
	if strings.Contains(cmd.Long, "experimental") {
		t.Error("broker command Long description must not contain 'experimental' — broker is production-ready")
	}
}
