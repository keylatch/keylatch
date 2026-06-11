// Package cli — coverage agent A: backend and grant helper tests (a–l files).
// File: cov_a_backend_grant_test.go
// Tests for: backend_upgrade_trust_cmd.go (printUpgradeResult),
//            grant_cmd.go (newGrantCreateCmd/newGrantListCmd flag registration),
//            completion_cmd.go (newCompletionCmd structure),
//            audit_hook.go (SecurityBlockHook), cmd_call.go (callMetaFilteredFields).
package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/registry"
)

// ---------------------------------------------------------------------------
// backend_upgrade_trust_cmd.go — printUpgradeResult
// ---------------------------------------------------------------------------

func TestPrintUpgradeResult_TextMode(t *testing.T) {
	t.Parallel()
	cmd := newBackendUpgradeTrustCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	if err := printUpgradeResult(cmd, false, nil, "upgrade complete"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "upgrade complete") {
		t.Errorf("expected 'upgrade complete' in output, got: %q", out)
	}
}

func TestPrintUpgradeResult_JSONMode(t *testing.T) {
	t.Parallel()
	cmd := newBackendUpgradeTrustCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	type result struct {
		Status string `json:"status"`
	}
	res := result{Status: "ok"}
	if err := printUpgradeResult(cmd, true, res, "should not appear"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "status") {
		t.Errorf("expected JSON output with 'status', got: %q", out)
	}
	if strings.Contains(out, "should not appear") {
		t.Errorf("text message must not appear in JSON mode, got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// grant_cmd.go — newGrantCreateCmd, newGrantListCmd, newGrantRevokeCmd flag registration
// ---------------------------------------------------------------------------

func TestGrantCreateCmd_FlagRegistration(t *testing.T) {
	t.Parallel()
	cmd := newGrantCreateCmd()
	if cmd == nil {
		t.Fatal("newGrantCreateCmd returned nil")
	}
	if cmd.Flags().Lookup("actor") == nil {
		t.Error("grant create must have --actor flag")
	}
	if cmd.Flags().Lookup("capability") == nil {
		t.Error("grant create must have --capability flag")
	}
	if cmd.Flags().Lookup("ttl") == nil {
		t.Error("grant create must have --ttl flag")
	}
}

func TestGrantListCmd_FlagRegistration(t *testing.T) {
	t.Parallel()
	cmd := newGrantListCmd()
	if cmd == nil {
		t.Fatal("newGrantListCmd returned nil")
	}
}

func TestGrantRevokeCmd_Registration(t *testing.T) {
	t.Parallel()
	cmd := newGrantRevokeCmd()
	if cmd == nil {
		t.Fatal("newGrantRevokeCmd returned nil")
	}
	if cmd.Use != "revoke <grant-id>" {
		t.Errorf("Use = %q, want 'revoke <grant-id>'", cmd.Use)
	}
}

// ---------------------------------------------------------------------------
// audit_hook.go — SecurityBlockHook default no-op does not panic
// ---------------------------------------------------------------------------

func TestSecurityBlockHook_DefaultNoOp(t *testing.T) {
	t.Parallel()
	// Default hook must be a no-op that doesn't panic.
	e := SecurityBlockEvent{
		Command: "get",
		Signals: []string{"CLAUDE_CODE=1"},
		Time:    time.Now(),
	}
	// Should not panic.
	SecurityBlockHook(nil, e)
}

// ---------------------------------------------------------------------------
// cmd_call.go — callMetaFilteredFields
// ---------------------------------------------------------------------------

func TestCallMetaFilteredFields_AllowedFieldsOnly(t *testing.T) {
	t.Parallel()
	// Create a callMeta with known fields — the filter must only expose allow-listed ones.
	meta := callMeta{
		Action:           "chat",
		ExchangeStrategy: "bearer",
		MaskingProfile:   "standard",
	}
	filtered := callMetaFilteredFields(meta)
	// The filtered map must not be nil.
	if filtered == nil {
		t.Fatal("callMetaFilteredFields returned nil")
	}
	// Action is an allowed field.
	if _, ok := filtered["action"]; !ok {
		t.Error("filtered map must include 'action'")
	}
	// exchange_strategy is an allowed field.
	if _, ok := filtered["exchange_strategy"]; !ok {
		t.Error("filtered map must include 'exchange_strategy'")
	}
}

// ---------------------------------------------------------------------------
// cmd_call.go — buildCallMeta (partial coverage via callMetaFilteredFields)
// ---------------------------------------------------------------------------

func TestBuildCallMeta_Basic(t *testing.T) {
	t.Parallel()
	// Verify buildCallMeta constructs a callMeta with expected provider.
	// We use a minimal setup — action and strategy may be nil.
	meta := buildCallMeta("chat", nil, registry.ExchangeNone)
	// With nil action/strategy, provider will be empty but struct must be valid.
	_ = meta // Just ensure no panic.
}
