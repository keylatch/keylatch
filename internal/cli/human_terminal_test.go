package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/gateway/approval"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/spf13/cobra"
)

func withInteractiveStdin(t *testing.T, interactive bool) {
	t.Helper()
	prev := interactiveStdin
	interactiveStdin = func() bool { return interactive }
	t.Cleanup(func() { interactiveStdin = prev })
}

func assertSecurityBlock(t *testing.T, err error) {
	t.Helper()
	var cliErr *CLIError
	if !errors.As(err, &cliErr) {
		t.Fatalf("expected *CLIError, got %T: %v", err, err)
	}
	if cliErr.Code != exitcode.SecurityBlock {
		t.Fatalf("exit code = %d, want SecurityBlock (%d)", cliErr.Code, exitcode.SecurityBlock)
	}
}

func assertStillPending(t *testing.T, approvalsDir, token string) {
	t.Helper()
	pending, err := approval.Pending(context.Background(), approvalsDir)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	for _, ar := range pending {
		if ar.Token == token {
			return
		}
	}
	t.Fatalf("approval %q must remain pending", token)
}

func TestHumanOnlyCommands_RefuseWithoutTerminal(t *testing.T) {
	cases := []struct {
		name string
		args func(token string) []string
		run  func() *cobra.Command
	}{
		{"approve", func(tok string) []string { return []string{tok} }, newApproveCmd},
		{"deny", func(tok string) []string { return []string{tok} }, newDenyCmd},
		{"deny --all --yes", func(string) []string { return []string{"--all", "--yes"} }, newDenyCmd},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			approvalsDir, _ := setupApprovalDir(t)
			t.Setenv("KEYLATCH_APPROVALS_DIR", approvalsDir)
			testutil.ClearLLMSessionEnv(t)
			withInteractiveStdin(t, false)
			token := createPendingApproval(t, approvalsDir)

			cmd := tc.run()
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetIn(strings.NewReader("y\n"))
			cmd.SetArgs(tc.args(token))

			err := cmd.ExecuteContext(context.Background())
			assertSecurityBlock(t, err)
			if !strings.Contains(err.Error(), "requires an interactive terminal") {
				t.Errorf("error should explain the terminal requirement, got %q", err)
			}
			assertStillPending(t, approvalsDir, token)
		})
	}
}

func TestHumanOnlyCommands_RefuseInDetectedSessionEvenWithTerminal(t *testing.T) {
	for _, signal := range []string{"CLAUDECODE", "CODEX_SANDBOX", "GEMINI_CLI", "OPENCODE", "CURSOR_AGENT"} {
		for name, newCmd := range map[string]func() *cobra.Command{"approve": newApproveCmd, "deny": newDenyCmd} {
			t.Run(name+"/"+signal, func(t *testing.T) {
				approvalsDir, _ := setupApprovalDir(t)
				t.Setenv("KEYLATCH_APPROVALS_DIR", approvalsDir)
				testutil.ClearLLMSessionEnv(t)
				t.Setenv(signal, "1")
				withInteractiveStdin(t, true)
				token := createPendingApproval(t, approvalsDir)

				cmd := newCmd()
				cmd.SetOut(&bytes.Buffer{})
				cmd.SetErr(&bytes.Buffer{})
				cmd.SetArgs([]string{token})

				err := cmd.ExecuteContext(context.Background())
				assertSecurityBlock(t, err)
				if !strings.Contains(err.Error(), "LLM session") {
					t.Errorf("error should name the LLM session block, got %q", err)
				}
				assertStillPending(t, approvalsDir, token)
			})
		}
	}
}
