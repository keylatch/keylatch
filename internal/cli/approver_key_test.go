package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/gateway/approval"
	"github.com/keylatch/keylatch/internal/testutil"
)

func runApprovalCmd(t *testing.T, args ...string) error {
	t.Helper()
	root := NewRootCommand()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetIn(bytes.NewReader(nil))
	root.SetArgs(args)
	return root.ExecuteContext(context.Background())
}

func requireCLICode(t *testing.T, err error, code int) {
	t.Helper()
	var cliErr *CLIError
	if !errors.As(err, &cliErr) {
		t.Fatalf("expected *CLIError, got %T: %v", err, err)
	}
	if cliErr.Code != code {
		t.Fatalf("exit code = %d, want %d (%s)", cliErr.Code, code, cliErr.Message)
	}
}

func requireStatus(t *testing.T, dir, token, want string) *approval.ApprovalRequest {
	t.Helper()
	ar, err := approval.Get(context.Background(), dir, token)
	if err != nil {
		t.Fatal(err)
	}
	if ar.Status != want {
		t.Fatalf("status = %q, want %q", ar.Status, want)
	}
	return ar
}

func approvalTestEnv(t *testing.T) string {
	t.Helper()
	dir, _ := setupApprovalDir(t)
	t.Setenv("KEYLATCH_APPROVALS_DIR", dir)
	testutil.ClearLLMSessionEnv(t)
	withInteractiveStdin(t, true)
	return dir
}

func TestApproveSignsWithApproverKey(t *testing.T) {
	dir := approvalTestEnv(t)
	pub := withApprover(t)
	token := createPendingApproval(t, dir)

	if err := runApprovalCmd(t, "approve", token); err != nil {
		t.Fatal(err)
	}
	if err := approval.Verify(context.Background(), dir, token, "hash123", pub); err != nil {
		t.Fatalf("approval made by the CLI does not verify: %v", err)
	}
}

func TestApproveWithoutApproverKeyIsRefused(t *testing.T) {
	dir := approvalTestEnv(t)
	t.Setenv("KEYLATCH_CONFIG_DIR", t.TempDir())
	withHiddenAnswers(t, testApproverPassphrase)
	token := createPendingApproval(t, dir)

	for _, args := range [][]string{{"approve", token}, {"deny", token}, {"deny", "--all", "--yes"}} {
		requireCLICode(t, runApprovalCmd(t, args...), exitcode.UserError)
	}
	requireStatus(t, dir, token, approval.StatusPending)
}

func TestApproveRejectsWrongPassphrase(t *testing.T) {
	dir := approvalTestEnv(t)
	withApprover(t)
	withHiddenAnswers(t, "not the approver passphrase")
	token := createPendingApproval(t, dir)

	for _, args := range [][]string{{"approve", token}, {"deny", token}, {"deny", "--all", "--yes"}} {
		requireCLICode(t, runApprovalCmd(t, args...), exitcode.SecurityBlock)
	}
	requireStatus(t, dir, token, approval.StatusPending)
}

func TestApproveRejectsMalformedTokenBeforePrompting(t *testing.T) {
	dir := approvalTestEnv(t)
	withApprover(t)
	prompted := false
	prev := promptHiddenFn
	promptHiddenFn = func() ([]byte, error) { prompted = true; return prev() }
	t.Cleanup(func() { promptHiddenFn = prev })

	victim := filepath.Join(filepath.Dir(dir), "outside.json")
	if err := os.WriteFile(victim, []byte(`{"status":"pending"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{"../outside", "apv_../../outside", "apv_short"} {
		requireCLICode(t, runApprovalCmd(t, "approve", tok), exitcode.Missing)
		requireCLICode(t, runApprovalCmd(t, "deny", tok), exitcode.Missing)
	}
	if prompted {
		t.Fatal("asked for the approver passphrase for a malformed token")
	}
	if got, _ := os.ReadFile(victim); string(got) != `{"status":"pending"}` {
		t.Fatalf("file outside the approvals directory changed: %s", got)
	}
}

func TestApproveDecidedRequestIsRefusedBeforePrompting(t *testing.T) {
	dir := approvalTestEnv(t)
	withApprover(t)
	token := createPendingApproval(t, dir)
	if err := approval.Deny(context.Background(), dir, token, shownOf(t, dir, token), testDecisionKey); err != nil {
		t.Fatal(err)
	}
	prev := promptHiddenFn
	promptHiddenFn = func() ([]byte, error) { t.Fatal("prompted for a decided request"); return nil, nil }
	t.Cleanup(func() { promptHiddenFn = prev })

	requireCLICode(t, runApprovalCmd(t, "approve", token), exitcode.UserError)
}

func TestDenyAllSignsEachDenial(t *testing.T) {
	dir := approvalTestEnv(t)
	pub := withApprover(t)
	first := createPendingApproval(t, dir)
	second := createPendingApproval(t, dir)

	if err := runApprovalCmd(t, "deny", "--all", "--yes"); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{first, second} {
		requireStatus(t, dir, token, approval.StatusDenied)
		// A signed denial passes the signature check and fails on status.
		err := approval.Verify(context.Background(), dir, token, "hash123", pub)
		if err == nil || errors.Is(err, approval.ErrUnsigned) || !strings.Contains(err.Error(), "not approved") {
			t.Fatalf("Verify on a denial = %v", err)
		}
	}
}

func TestApproveInitSetsPassphrase(t *testing.T) {
	approvalTestEnv(t)
	withCheapApproverKDF(t)
	configDir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", configDir)
	withHiddenAnswers(t, testApproverPassphrase)

	if err := runApprovalCmd(t, "approve", "init"); err != nil {
		t.Fatal(err)
	}
	key, err := approval.LoadApproverKey(filepath.Join(configDir, "approver.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := key.Unlock([]byte(testApproverPassphrase)); err != nil {
		t.Fatalf("stored key does not unlock with the chosen passphrase: %v", err)
	}
}

func TestApproveInitRejectsBadPassphrases(t *testing.T) {
	approvalTestEnv(t)
	withCheapApproverKDF(t)
	configDir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", configDir)

	withHiddenAnswers(t, "short")
	requireCLICode(t, runApprovalCmd(t, "approve", "init"), exitcode.UserError)

	prev := promptHiddenFn
	answers := []string{testApproverPassphrase, testApproverPassphrase + "x"}
	promptHiddenFn = func() ([]byte, error) { a := answers[0]; answers = answers[1:]; return []byte(a), nil }
	t.Cleanup(func() { promptHiddenFn = prev })
	requireCLICode(t, runApprovalCmd(t, "approve", "init"), exitcode.UserError)

	if _, err := os.Stat(filepath.Join(configDir, "approver.json")); !os.IsNotExist(err) {
		t.Fatalf("approver key written despite a rejected passphrase: %v", err)
	}
}

func TestApproveInitChangeNeedsCurrentPassphrase(t *testing.T) {
	approvalTestEnv(t)
	withApprover(t)
	path := approverKeyPath(func(k string) string { return os.Getenv(k) })
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	withHiddenAnswers(t, "a guessed passphrase", "attacker passphrase")
	requireCLICode(t, runApprovalCmd(t, "approve", "init"), exitcode.SecurityBlock)
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("approver key replaced without the current passphrase")
	}

	withHiddenAnswers(t, testApproverPassphrase, "a brand new passphrase")
	if err := runApprovalCmd(t, "approve", "init"); err != nil {
		t.Fatal(err)
	}
	key, err := approval.LoadApproverKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := key.Unlock([]byte("a brand new passphrase")); err != nil {
		t.Fatalf("new passphrase does not unlock: %v", err)
	}
}

func TestApproveInitIsHumanOnly(t *testing.T) {
	approvalTestEnv(t)
	withCheapApproverKDF(t)
	t.Setenv("KEYLATCH_CONFIG_DIR", t.TempDir())
	withHiddenAnswers(t, testApproverPassphrase)

	withInteractiveStdin(t, false)
	requireCLICode(t, runApprovalCmd(t, "approve", "init"), exitcode.SecurityBlock)

	withInteractiveStdin(t, true)
	t.Setenv("CLAUDECODE", "1")
	requireCLICode(t, runApprovalCmd(t, "approve", "init"), exitcode.SecurityBlock)
}
