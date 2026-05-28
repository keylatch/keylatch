package policy_test

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/policy"
	"github.com/keylatch/keylatch/internal/runner"
)

// openTestAuditLogger creates a temporary audit logger for tests.
func openTestAuditLogger(t *testing.T) *audit.Logger {
	t.Helper()
	dir := t.TempDir()
	// Audit package requires parent directory mode 0o700.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	logPath := filepath.Join(dir, "audit.log")

	// Generate a random salt and DEK for the test.
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("generate salt: %v", err)
	}
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("generate dek: %v", err)
	}

	logger, err := audit.Open(logPath, salt, dek)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { logger.Close() })
	return logger
}

// writeFileMode writes data to path with the specified file mode.
func writeFileMode(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// savePolicyForTest saves p to a temp dir and returns the policy file path.
func savePolicyForTest(t *testing.T, p policy.Policy) string {
	t.Helper()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	if err := policy.Save(policyPath, p); err != nil {
		t.Fatalf("save policy: %v", err)
	}
	return policyPath
}

// TestAuditEmitsOnePolicyCheckEvent verifies that every CheckPolicyWithAudit
// call emits exactly one ActionPolicyCheck event.
func TestAuditEmitsOnePolicyCheckEvent(t *testing.T) {
	logger := openTestAuditLogger(t)
	ctx := context.Background()

	policyPath := savePolicyForTest(t, policy.Policy{
		SchemaVersion: 1,
		Mode:          policy.ModeEnforcing,
		DefaultDeny:   true,
	})

	opts := runner.PolicyOptions{
		PolicyPath: policyPath,
		Capability: "inject",
	}

	// Emit three policy checks.
	for i := 0; i < 3; i++ {
		_, _ = runner.CheckPolicyWithAudit(ctx, logger, "openrouter:dev", nil, opts)
	}

	sum, err := logger.Summarize(audit.SummaryOpts{Action: audit.ActionPolicyCheck})
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if sum.TotalEvents != 3 {
		t.Errorf("expected 3 ActionPolicyCheck events, got %d", sum.TotalEvents)
	}
}

// TestAuditPolicyCheck_DenyEmitsDenied verifies deny decisions emit OutcomeDenied.
func TestAuditPolicyCheck_DenyEmitsDenied(t *testing.T) {
	logger := openTestAuditLogger(t)
	ctx := context.Background()

	policyPath := savePolicyForTest(t, policy.Policy{
		SchemaVersion: 1,
		Mode:          policy.ModeEnforcing,
		DefaultDeny:   true, // will deny — no rules
	})

	opts := runner.PolicyOptions{
		PolicyPath: policyPath,
		Capability: "inject",
	}

	_, _ = runner.CheckPolicyWithAudit(ctx, logger, "openrouter:dev", nil, opts)

	sum, err := logger.Summarize(audit.SummaryOpts{Action: audit.ActionPolicyCheck})
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if sum.TotalEvents != 1 {
		t.Errorf("expected 1 event, got %d", sum.TotalEvents)
	}
	if sum.ByOutcome[audit.OutcomeDenied] != 1 {
		t.Errorf("expected 1 denied event, got %v", sum.ByOutcome)
	}
}

// TestAuditPolicyCheck_AllowEmitsOK verifies allow decisions emit OutcomeOK.
func TestAuditPolicyCheck_AllowEmitsOK(t *testing.T) {
	logger := openTestAuditLogger(t)
	ctx := context.Background()

	policyPath := savePolicyForTest(t, policy.Policy{
		SchemaVersion: 1,
		Mode:          policy.ModeEnforcing,
		DefaultDeny:   false, // will allow (default-allow, no rules)
	})

	opts := runner.PolicyOptions{
		PolicyPath: policyPath,
		Capability: "inject",
	}

	_, _ = runner.CheckPolicyWithAudit(ctx, logger, "openrouter:dev", nil, opts)

	sum, err := logger.Summarize(audit.SummaryOpts{Action: audit.ActionPolicyCheck})
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if sum.ByOutcome[audit.OutcomeOK] != 1 {
		t.Errorf("expected 1 OK event, got %v", sum.ByOutcome)
	}
}
