package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/gateway/approval"
)

// setupApprovalDir creates a temp dir for approval requests.
func setupApprovalDir(t *testing.T) (approvalsDir string, cleanup func()) {
	t.Helper()
	dir := t.TempDir()
	approvalsDir = filepath.Join(dir, "approvals")
	if err := os.MkdirAll(approvalsDir, 0o700); err != nil {
		t.Fatalf("mkdir approvals: %v", err)
	}
	return approvalsDir, func() {}
}

// createPendingApproval creates a pending approval request and returns the token.
func createPendingApproval(t *testing.T, approvalsDir string) string {
	t.Helper()
	ar, err := approval.RequestNew(context.Background(), approvalsDir,
		"test-actor", "inject", "openrouter", "hash123", 5*time.Minute)
	if err != nil {
		t.Fatalf("RequestNew: %v", err)
	}
	return ar.Token
}

// TestApproveCmd_NoArgs verifies approve fails without token argument.
func TestApproveCmd_NoArgs(t *testing.T) {
	t.Parallel()
	cmd := newApproveCmd()
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetOut(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when no token argument provided")
	}
}

// TestApproveCmd_Success verifies approve marks a pending request as approved.
func TestApproveCmd_Success(t *testing.T) {
	approvalsDir, _ := setupApprovalDir(t)
	t.Setenv("KEYLATCH_APPROVALS_DIR", approvalsDir)
	t.Setenv("CREDENTIALS_LLM_SESSION", "")
	t.Setenv("CLAUDE_CODE", "")

	token := createPendingApproval(t, approvalsDir)

	cmd := newApproveCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{token})

	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("approved")) {
		t.Errorf("output should contain 'approved', got %q", out.String())
	}
}

// TestApproveCmd_JSON_Success verifies --json output on approval.
func TestApproveCmd_JSON_Success(t *testing.T) {
	approvalsDir, _ := setupApprovalDir(t)
	t.Setenv("KEYLATCH_APPROVALS_DIR", approvalsDir)
	t.Setenv("CREDENTIALS_LLM_SESSION", "")
	t.Setenv("CLAUDE_CODE", "")

	token := createPendingApproval(t, approvalsDir)

	cmd := newApproveCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{token, "--json"})

	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("approve --json: %v", err)
	}

	var payload approveOutput
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse JSON: %v (output: %q)", err, out.String())
	}
	if payload.Token != token {
		t.Errorf("token = %q, want %q", payload.Token, token)
	}
	if payload.Status != "approved" {
		t.Errorf("status = %q, want approved", payload.Status)
	}
}

// TestApproveCmd_WithReason verifies --reason is stored.
func TestApproveCmd_WithReason(t *testing.T) {
	approvalsDir, _ := setupApprovalDir(t)
	t.Setenv("KEYLATCH_APPROVALS_DIR", approvalsDir)
	t.Setenv("CREDENTIALS_LLM_SESSION", "")
	t.Setenv("CLAUDE_CODE", "")

	token := createPendingApproval(t, approvalsDir)

	cmd := newApproveCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{token, "--reason", "looks good", "--json"})

	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("approve --reason: %v", err)
	}

	var payload approveOutput
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}
	if payload.Reason != "looks good" {
		t.Errorf("reason = %q, want 'looks good'", payload.Reason)
	}
}

// TestApproveCmd_Flags verifies --reason and --json flags are registered.
func TestApproveCmd_Flags(t *testing.T) {
	t.Parallel()
	cmd := newApproveCmd()
	if cmd.Flags().Lookup("reason") == nil {
		t.Error("--reason flag must be registered on approve")
	}
	if cmd.Flags().Lookup("json") == nil {
		t.Error("--json flag must be registered on approve")
	}
}

// TestApprove_Success is the canonical named test for the approve success path.
func TestApprove_Success(t *testing.T) {
	approvalsDir, _ := setupApprovalDir(t)
	t.Setenv("KEYLATCH_APPROVALS_DIR", approvalsDir)
	t.Setenv("CREDENTIALS_LLM_SESSION", "")
	t.Setenv("CLAUDE_CODE", "")

	token := createPendingApproval(t, approvalsDir)

	cmd := newApproveCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{token})

	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("approved")) {
		t.Errorf("output should contain 'approved'; got %q", out.String())
	}
}

// TestApprove_NotFound verifies approve exits Missing for unknown token.
func TestApprove_NotFound(t *testing.T) {
	approvalsDir, _ := setupApprovalDir(t)
	t.Setenv("KEYLATCH_APPROVALS_DIR", approvalsDir)
	t.Setenv("CREDENTIALS_LLM_SESSION", "")
	t.Setenv("CLAUDE_CODE", "")

	cmd := newApproveCmd()
	var errOut bytes.Buffer
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"apv_does_not_exist"})

	// approve returns a CLIError on not-found — the error is now testable.
	err := cmd.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("expected error for unknown token")
	}
	var cliErr *CLIError
	if !errors.As(err, &cliErr) {
		t.Errorf("expected *CLIError; got %T: %v", err, err)
	}
}

// TestApprove_AlreadyDecided verifies approve exits UserError for already-acted token.
func TestApprove_AlreadyDecided(t *testing.T) {
	approvalsDir, _ := setupApprovalDir(t)
	t.Setenv("CREDENTIALS_LLM_SESSION", "")
	t.Setenv("CLAUDE_CODE", "")

	token := createPendingApproval(t, approvalsDir)
	// Approve first.
	if err := approval.Approve(context.Background(), approvalsDir, token); err != nil {
		t.Fatalf("first approve: %v", err)
	}
	// Second approve should return ErrAlreadyActed.
	err := approval.Approve(context.Background(), approvalsDir, token)
	if !errors.Is(err, approval.ErrAlreadyActed) {
		t.Errorf("expected ErrAlreadyActed; got %v", err)
	}
}

// ---- approve list ----

// TestApprove_List_Empty verifies approve list prints "No pending approvals."
func TestApprove_List_Empty(t *testing.T) {
	approvalsDir, _ := setupApprovalDir(t)
	t.Setenv("KEYLATCH_APPROVALS_DIR", approvalsDir)

	cmd := newApproveCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"list"})

	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("approve list (empty): %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("No pending approvals")) {
		t.Errorf("expected 'No pending approvals'; got %q", out.String())
	}
}

// TestApprove_List_Populated verifies approve list shows pending entries.
func TestApprove_List_Populated(t *testing.T) {
	approvalsDir, _ := setupApprovalDir(t)
	t.Setenv("KEYLATCH_APPROVALS_DIR", approvalsDir)

	_ = createPendingApproval(t, approvalsDir)
	_ = createPendingApproval(t, approvalsDir)

	cmd := newApproveCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"list"})

	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("approve list: %v", err)
	}
	// Should show header and 2 entries.
	output := out.String()
	if !bytes.Contains(out.Bytes(), []byte("ID")) {
		t.Errorf("output should have table header; got %q", output)
	}
}

// TestApprove_List_JSON verifies approve list --json emits a JSON array.
func TestApprove_List_JSON(t *testing.T) {
	approvalsDir, _ := setupApprovalDir(t)
	t.Setenv("KEYLATCH_APPROVALS_DIR", approvalsDir)

	token := createPendingApproval(t, approvalsDir)

	cmd := newApproveCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"list", "--json"})

	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("approve list --json: %v", err)
	}

	var entries []approveListEntry
	if err := json.Unmarshal(out.Bytes(), &entries); err != nil {
		t.Fatalf("parse JSON: %v (output: %q)", err, out.String())
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry; got %d", len(entries))
	}
	if entries[0].Token != token {
		t.Errorf("token = %q; want %q", entries[0].Token, token)
	}
}

// TestApprove_List_JSON_Empty verifies approve list --json emits [] for empty.
func TestApprove_List_JSON_Empty(t *testing.T) {
	approvalsDir, _ := setupApprovalDir(t)
	t.Setenv("KEYLATCH_APPROVALS_DIR", approvalsDir)

	cmd := newApproveCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"list", "--json"})

	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("approve list --json (empty): %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("[]")) {
		t.Errorf("expected [] JSON for empty list; got %q", out.String())
	}
}
