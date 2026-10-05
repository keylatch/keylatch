package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/gateway/approval"
)

// swapDuringPrompt rewrites the request with the agent's own values while
// the approver is typing the passphrase.
func swapDuringPrompt(t *testing.T, dir, token string) {
	t.Helper()
	prev := promptHiddenFn
	promptHiddenFn = func() ([]byte, error) {
		path := filepath.Join(dir, token+".json")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var ar approval.ApprovalRequest
		if err := json.Unmarshal(data, &ar); err != nil {
			t.Fatal(err)
		}
		ar.Connection = "prod-db"
		ar.Capability = "export"
		swapped, _ := json.Marshal(ar)
		if err := os.WriteFile(path, swapped, 0o600); err != nil {
			t.Fatal(err)
		}
		return slices.Clone([]byte(testApproverPassphrase)), nil
	}
	t.Cleanup(func() { promptHiddenFn = prev })
}

func TestApproveRefusesRequestSwappedDuringPrompt(t *testing.T) {
	for _, command := range []string{"approve", "deny"} {
		t.Run(command, func(t *testing.T) {
			dir := approvalTestEnv(t)
			withApprover(t)
			token := createPendingApproval(t, dir)
			swapDuringPrompt(t, dir, token)

			requireCLICode(t, runApprovalCmd(t, command, token), exitcode.SecurityBlock)
			ar := requireStatus(t, dir, token, approval.StatusPending)
			if ar.Signature != "" {
				t.Fatal("swapped request was signed")
			}
		})
	}
}

func TestApprovalDisplayStripsControlCharacters(t *testing.T) {
	dir := approvalTestEnv(t)
	ar, err := approval.RequestNew(context.Background(), dir,
		"agent\x1b[2K\rgithub-readonly", "read\u202e", "prod\x1b]0;x\x07-db", "hash", 0)
	if err != nil {
		t.Fatal(err)
	}

	var summary bytes.Buffer
	printApprovalSummary(&summary, ar)

	root := NewRootCommand()
	var list bytes.Buffer
	root.SetOut(&list)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"approve", "list"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}

	for name, out := range map[string]string{"summary": summary.String(), "list": list.String()} {
		if strings.ContainsAny(out, "\x1b\r\x07\u202e") {
			t.Fatalf("%s carries control characters: %q", name, out)
		}
		if !strings.Contains(out, "prod]0;x-db") {
			t.Fatalf("%s lost the visible text: %q", name, out)
		}
	}
	if !strings.Contains(summary.String(), "hash") {
		t.Fatalf("summary does not show the request hash: %q", summary.String())
	}
}
