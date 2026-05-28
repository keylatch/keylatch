package policy_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/policy"
	"github.com/keylatch/keylatch/internal/trust"
)

func TestRootRequirement_JSONRoundTrip(t *testing.T) {
	rr := policy.RootRequirement{
		Type:      "any",
		AnyOf:     []string{"secure_enclave", "fido2"},
		MaxAgeSec: 300,
		Bind:      "command",
		TwoPerson: false,
	}
	b, err := json.Marshal(rr)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out policy.RootRequirement
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Type != rr.Type {
		t.Errorf("Type: got %q, want %q", out.Type, rr.Type)
	}
	if len(out.AnyOf) != len(rr.AnyOf) {
		t.Errorf("AnyOf len: got %d, want %d", len(out.AnyOf), len(rr.AnyOf))
	}
	if out.MaxAgeSec != rr.MaxAgeSec {
		t.Errorf("MaxAgeSec: got %d, want %d", out.MaxAgeSec, rr.MaxAgeSec)
	}
}

func TestRootRequirement_AllOf_JSONRoundTrip(t *testing.T) {
	rr := policy.RootRequirement{
		Type:      "all",
		AllOf:     []string{"yubikey-root-1", "phone-fido2"},
		MaxAgeSec: 600,
		TwoPerson: true,
	}
	b, err := json.Marshal(rr)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out policy.RootRequirement
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.TwoPerson != rr.TwoPerson {
		t.Errorf("TwoPerson: got %v, want %v", out.TwoPerson, rr.TwoPerson)
	}
	if len(out.AllOf) != 2 {
		t.Errorf("AllOf len: got %d, want 2", len(out.AllOf))
	}
}

func TestCheck_ApprovalRootReq_AnyOf(t *testing.T) {
	p := policy.Policy{
		SchemaVersion: 1,
		Mode:          policy.ModeEnforcing,
		Rules: []policy.Rule{
			{
				ID:           "rule-hardware",
				Actor:        "*",
				Connections:  []string{"*"},
				Capabilities: []string{"inject"},
				CreatedAt:    time.Now(),
				ApprovalRootReq: &policy.RootRequirement{
					Type:      "any",
					AnyOf:     []string{"secure_enclave", "fido2"},
					MaxAgeSec: 300,
				},
			},
		},
	}

	req := policy.Request{
		Actor:      "alice",
		Connection: "prod",
		Capability: "inject",
	}
	d := p.Check(req)
	if !d.Allow {
		t.Error("expected Allow=true")
	}
	if !d.ApprovalRequired {
		t.Error("expected ApprovalRequired=true")
	}
	if d.ApprovalRootReq == nil {
		t.Fatal("expected ApprovalRootReq to be set")
	}
	if d.ApprovalRootReq.Type != "any" {
		t.Errorf("ApprovalRootReq.Type = %q, want %q", d.ApprovalRootReq.Type, "any")
	}
}

func TestCheck_ApprovalRootReq_AllOf(t *testing.T) {
	p := policy.Policy{
		SchemaVersion: 1,
		Mode:          policy.ModeEnforcing,
		Rules: []policy.Rule{
			{
				ID:           "rule-two-person",
				Actor:        "*",
				Connections:  []string{"*"},
				Capabilities: []string{"delete"},
				Approval:     true,
				CreatedAt:    time.Now(),
				ApprovalRootReq: &policy.RootRequirement{
					Type:      "all",
					AllOf:     []string{"yubikey-1", "yubikey-2"},
					TwoPerson: true,
				},
			},
		},
	}

	req := policy.Request{
		Actor:      "admin",
		Connection: "prod",
		Capability: "delete",
	}
	d := p.Check(req)
	if !d.Allow {
		t.Error("expected Allow=true")
	}
	if !d.ApprovalRequired {
		t.Error("expected ApprovalRequired=true")
	}
	if d.ApprovalRootReq == nil {
		t.Fatal("expected ApprovalRootReq to be set")
	}
	if !d.ApprovalRootReq.TwoPerson {
		t.Error("expected TwoPerson=true")
	}
}

// TestCheck_MaxAgeSec_FreshProof verifies that a fresh PresenceProof within MaxAgeSec is accepted.
func TestCheck_MaxAgeSec_FreshProof(t *testing.T) {
	p := policy.Policy{
		SchemaVersion: 1,
		Mode:          policy.ModeEnforcing,
		Rules: []policy.Rule{
			{
				ID:           "rule-maxage",
				Actor:        "*",
				Connections:  []string{"*"},
				Capabilities: []string{"inject"},
				CreatedAt:    time.Now(),
				ApprovalRootReq: &policy.RootRequirement{
					Type:      "any",
					AnyOf:     []string{"secure_enclave"},
					MaxAgeSec: 300,
				},
			},
		},
	}

	freshProof := &trust.PresenceProof{
		Method:      "ssh-agent",
		ConfirmedAt: time.Now().UTC().Add(-10 * time.Second), // 10s ago — within 300s
		RootID:      "hmac-root-id",
	}

	req := policy.Request{
		Actor:         "alice",
		Connection:    "prod",
		Capability:    "inject",
		PresenceProof: freshProof,
	}
	d := p.Check(req)
	if !d.Allow {
		t.Errorf("expected Allow=true for fresh proof, got reason: %s", d.Reason)
	}
}

// TestCheck_MaxAgeSec_StaleProof verifies that a stale PresenceProof beyond MaxAgeSec is rejected.
func TestCheck_MaxAgeSec_StaleProof(t *testing.T) {
	p := policy.Policy{
		SchemaVersion: 1,
		Mode:          policy.ModeEnforcing,
		Rules: []policy.Rule{
			{
				ID:           "rule-maxage-stale",
				Actor:        "*",
				Connections:  []string{"*"},
				Capabilities: []string{"inject"},
				CreatedAt:    time.Now(),
				ApprovalRootReq: &policy.RootRequirement{
					Type:      "any",
					AnyOf:     []string{"secure_enclave"},
					MaxAgeSec: 60, // 1 minute
				},
			},
		},
	}

	staleProof := &trust.PresenceProof{
		Method:      "ssh-agent",
		ConfirmedAt: time.Now().UTC().Add(-2 * time.Minute), // 2 minutes ago — beyond 60s
		RootID:      "hmac-root-id",
	}

	req := policy.Request{
		Actor:         "alice",
		Connection:    "prod",
		Capability:    "inject",
		PresenceProof: staleProof,
	}
	d := p.Check(req)
	if d.Allow {
		t.Error("expected Allow=false for stale proof")
	}
	if d.Reason == "" {
		t.Error("expected non-empty Reason for stale proof denial")
	}
}

// TestCheck_TwoPerson_BindingMismatch verifies that TwoPerson rule rejects proof with empty RootID.
func TestCheck_TwoPerson_BindingMismatch(t *testing.T) {
	p := policy.Policy{
		SchemaVersion: 1,
		Mode:          policy.ModeEnforcing,
		Rules: []policy.Rule{
			{
				ID:           "rule-two-person-binding",
				Actor:        "*",
				Connections:  []string{"*"},
				Capabilities: []string{"delete"},
				CreatedAt:    time.Now(),
				ApprovalRootReq: &policy.RootRequirement{
					Type:      "all",
					AllOf:     []string{"root-a", "root-b"},
					TwoPerson: true,
				},
			},
		},
	}

	// Proof with empty RootID — binding mismatch for two-person.
	badProof := &trust.PresenceProof{
		Method:      "ssh-agent",
		ConfirmedAt: time.Now().UTC(),
		RootID:      "", // missing
	}

	req := policy.Request{
		Actor:         "admin",
		Connection:    "prod",
		Capability:    "delete",
		PresenceProof: badProof,
	}
	d := p.Check(req)
	if d.Allow {
		t.Error("expected Allow=false for binding mismatch")
	}
}

func TestCheck_NoApprovalRootReq(t *testing.T) {
	p := policy.Policy{
		SchemaVersion: 1,
		Mode:          policy.ModeEnforcing,
		Rules: []policy.Rule{
			{
				ID:           "plain-rule",
				Actor:        "*",
				Connections:  []string{"*"},
				Capabilities: []string{"status"},
				CreatedAt:    time.Now(),
			},
		},
	}
	req := policy.Request{Actor: "alice", Connection: "prod", Capability: "status"}
	d := p.Check(req)
	if !d.Allow {
		t.Error("expected Allow=true")
	}
	if d.ApprovalRequired {
		t.Error("expected ApprovalRequired=false for plain allow rule")
	}
	if d.ApprovalRootReq != nil {
		t.Error("expected ApprovalRootReq=nil for plain allow rule")
	}
}
