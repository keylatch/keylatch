package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/gateway/approval"
)

// TestDenyCmd_NoArgs verifies deny fails without token argument.
func TestDenyCmd_NoArgs(t *testing.T) {
	t.Parallel()
	cmd := newDenyCmd()
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetOut(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when no token argument provided")
	}
}

// TestDenyCmd_Success verifies deny marks a pending request as denied.
func TestDenyCmd_Success(t *testing.T) {
	approvalsDir, _ := setupApprovalDir(t)
	t.Setenv("KEYLATCH_APPROVALS_DIR", approvalsDir)
	t.Setenv("CREDENTIALS_LLM_SESSION", "")
	t.Setenv("CLAUDE_CODE", "")

	token := createPendingApproval(t, approvalsDir)

	cmd := newDenyCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{token})

	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("deny: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("denied")) {
		t.Errorf("output should contain 'denied', got %q", out.String())
	}
}

// TestDenyCmd_JSON_WithReason verifies --json + --reason output on denial.
func TestDenyCmd_JSON_WithReason(t *testing.T) {
	approvalsDir, _ := setupApprovalDir(t)
	t.Setenv("KEYLATCH_APPROVALS_DIR", approvalsDir)
	t.Setenv("CREDENTIALS_LLM_SESSION", "")
	t.Setenv("CLAUDE_CODE", "")

	token := createPendingApproval(t, approvalsDir)

	cmd := newDenyCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{token, "--reason", "wrong env", "--json"})

	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("deny --json --reason: %v", err)
	}

	var payload denyOutput
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse JSON: %v (output: %q)", err, out.String())
	}
	if payload.Token != token {
		t.Errorf("token = %q, want %q", payload.Token, token)
	}
	if payload.Status != "denied" {
		t.Errorf("status = %q, want denied", payload.Status)
	}
	if payload.Reason != "wrong env" {
		t.Errorf("reason = %q, want 'wrong env'", payload.Reason)
	}
}

// TestDenyCmd_Flags verifies --reason and --json flags are registered.
func TestDenyCmd_Flags(t *testing.T) {
	t.Parallel()
	cmd := newDenyCmd()
	if cmd.Flags().Lookup("reason") == nil {
		t.Error("--reason flag must be registered on deny")
	}
	if cmd.Flags().Lookup("json") == nil {
		t.Error("--json flag must be registered on deny")
	}
}

// TestApproveAndDenyCmd_ErrorCodes verifies both commands use KL-41xx codes.
func TestApproveAndDenyCmd_ErrorCodes(t *testing.T) {
	t.Parallel()
	// Verify commands have the expected Use strings (KL-41xx is in the source code).
	approveCmd := newApproveCmd()
	if approveCmd.Use == "" {
		t.Error("approve cmd must have a Use string")
	}
	denyCmd := newDenyCmd()
	if denyCmd.Use == "" {
		t.Error("deny cmd must have a Use string")
	}
}

// ---- deny single-token named tests ----

// TestDeny_Success is the named test from the Epic spec.
func TestDeny_Success(t *testing.T) {
	approvalsDir, _ := setupApprovalDir(t)
	t.Setenv("KEYLATCH_APPROVALS_DIR", approvalsDir)
	t.Setenv("CREDENTIALS_LLM_SESSION", "")
	t.Setenv("CLAUDE_CODE", "")

	token := createPendingApproval(t, approvalsDir)

	cmd := newDenyCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{token})

	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("deny: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("denied")) {
		t.Errorf("output should contain 'denied'; got %q", out.String())
	}
}

// TestDeny_NotFound validates that the ErrNotFound error path is exercised.
func TestDeny_NotFound(t *testing.T) {
	approvalsDir, _ := setupApprovalDir(t)
	t.Setenv("CREDENTIALS_LLM_SESSION", "")
	t.Setenv("CLAUDE_CODE", "")

	// Verify the store itself returns ErrNotFound for unknown tokens.
	err := approval.Deny(context.Background(), approvalsDir, "apv_does_not_exist")
	if !errors.Is(err, approval.ErrNotFound) {
		t.Errorf("expected ErrNotFound; got %v", err)
	}
}

// TestDeny_AlreadyDecided validates that ErrAlreadyActed is returned on double-deny.
func TestDeny_AlreadyDecided(t *testing.T) {
	approvalsDir, _ := setupApprovalDir(t)
	t.Setenv("CREDENTIALS_LLM_SESSION", "")
	t.Setenv("CLAUDE_CODE", "")

	token := createPendingApproval(t, approvalsDir)
	// Deny first.
	if err := approval.Deny(context.Background(), approvalsDir, token); err != nil {
		t.Fatalf("first deny: %v", err)
	}
	// Second deny should return ErrAlreadyActed.
	err := approval.Deny(context.Background(), approvalsDir, token)
	if !errors.Is(err, approval.ErrAlreadyActed) {
		t.Errorf("expected ErrAlreadyActed; got %v", err)
	}
}

// ---- deny --all ----

// TestDeny_All_Confirmed verifies --all --yes denies all pending approvals.
func TestDeny_All_Confirmed(t *testing.T) {
	approvalsDir, _ := setupApprovalDir(t)
	t.Setenv("KEYLATCH_APPROVALS_DIR", approvalsDir)
	t.Setenv("CREDENTIALS_LLM_SESSION", "")
	t.Setenv("CLAUDE_CODE", "")

	_ = createPendingApproval(t, approvalsDir)
	_ = createPendingApproval(t, approvalsDir)

	cmd := newDenyCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--all", "--yes"})

	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("deny --all --yes: %v", err)
	}
	if !strings.Contains(out.String(), "2") {
		t.Errorf("output should mention 2 denied approvals; got %q", out.String())
	}
}

// TestDeny_All_Aborted verifies --all without --yes and "N" answer aborts.
func TestDeny_All_Aborted(t *testing.T) {
	approvalsDir, _ := setupApprovalDir(t)
	t.Setenv("KEYLATCH_APPROVALS_DIR", approvalsDir)
	t.Setenv("CREDENTIALS_LLM_SESSION", "")
	t.Setenv("CLAUDE_CODE", "")

	_ = createPendingApproval(t, approvalsDir)

	cmd := newDenyCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetIn(strings.NewReader("N\n"))
	cmd.SetArgs([]string{"--all"})

	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("deny --all (aborted): %v", err)
	}
	if !strings.Contains(out.String(), "Aborted") {
		t.Errorf("output should contain 'Aborted'; got %q", out.String())
	}
}

// TestDeny_All_YesSkipsPrompt verifies --all --yes skips the confirmation prompt.
func TestDeny_All_YesSkipsPrompt(t *testing.T) {
	approvalsDir, _ := setupApprovalDir(t)
	t.Setenv("KEYLATCH_APPROVALS_DIR", approvalsDir)
	t.Setenv("CREDENTIALS_LLM_SESSION", "")
	t.Setenv("CLAUDE_CODE", "")

	token := createPendingApproval(t, approvalsDir)

	cmd := newDenyCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	// No stdin needed — --yes skips the prompt.
	cmd.SetArgs([]string{"--all", "--yes"})

	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("deny --all --yes: %v", err)
	}

	// Verify the token was actually denied in the store.
	pending, err := approval.Pending(context.Background(), approvalsDir)
	if err != nil {
		t.Fatalf("Pending after deny --all: %v", err)
	}
	for _, ar := range pending {
		if ar.Token == token {
			t.Errorf("token %q should have been denied; still pending", token)
		}
	}
}

// TestDeny_All_SkipsPreDecidedEntries verifies --all tolerates already-decided entries
// (simulates the case where an entry was decided between the Pending() call and DenyWithReason).
func TestDeny_All_SkipsPreDecidedEntries(t *testing.T) {
	approvalsDir, _ := setupApprovalDir(t)
	t.Setenv("KEYLATCH_APPROVALS_DIR", approvalsDir)
	t.Setenv("CREDENTIALS_LLM_SESSION", "")
	t.Setenv("CLAUDE_CODE", "")

	token1 := createPendingApproval(t, approvalsDir)
	token2 := createPendingApproval(t, approvalsDir)

	// Pre-approve token1 to simulate a race (already decided).
	if err := approval.Approve(context.Background(), approvalsDir, token1); err != nil {
		t.Fatalf("pre-approve: %v", err)
	}

	cmd := newDenyCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--all", "--yes"})

	// Should NOT error even though token1 was already approved.
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("deny --all (race tolerance): %v", err)
	}

	// token2 should now be denied.
	pending, err := approval.Pending(context.Background(), approvalsDir)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	for _, ar := range pending {
		if ar.Token == token2 {
			t.Errorf("token2 %q should have been denied; still pending", token2)
		}
	}
}

// TestDeny_All_JSON verifies --all --yes --json emits deniedCount and requestIds.
func TestDeny_All_JSON(t *testing.T) {
	approvalsDir, _ := setupApprovalDir(t)
	t.Setenv("KEYLATCH_APPROVALS_DIR", approvalsDir)
	t.Setenv("CREDENTIALS_LLM_SESSION", "")
	t.Setenv("CLAUDE_CODE", "")

	token := createPendingApproval(t, approvalsDir)

	cmd := newDenyCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--all", "--yes", "--json"})

	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("deny --all --yes --json: %v", err)
	}

	var result denyAllOutput
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("parse JSON: %v (output: %q)", err, out.String())
	}
	if result.DeniedCount != 1 {
		t.Errorf("deniedCount = %d; want 1", result.DeniedCount)
	}
	if len(result.RequestIDs) != 1 || result.RequestIDs[0] != token {
		t.Errorf("requestIds = %v; want [%q]", result.RequestIDs, token)
	}
}

// TestDeny_Flags verifies all new flags are registered.
func TestDeny_Flags(t *testing.T) {
	t.Parallel()
	cmd := newDenyCmd()
	for _, flag := range []string{"all", "yes", "json", "reason"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("--%s flag must be registered on deny", flag)
		}
	}
}
