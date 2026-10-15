package runner

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/registry"
)

type auditGateway struct{}

func (auditGateway) Addr() string  { return "127.0.0.1:7878" }
func (auditGateway) Running() bool { return true }

// A session token keeps the caller's LLM classification, has a bounded number
// of uses, a short life, and is revoked as soon as the child exits.
func TestRunTokenRevokedOnExit(t *testing.T) {
	t.Setenv("CREDENTIALS_LLM_SESSION", "audit")
	path := filepath.Join(t.TempDir(), "tokens.json")
	d := NewGatewayTypedDriver(auditGateway{}, make([]byte, 32), path)
	_, err := d.Run(context.Background(), ExecRequest{Command: []string{"/bin/true"}}, registry.ConnectionTemplate{Provider: "audit"})
	if err != nil {
		t.Fatal(err)
	}
	records, err := token.List(token.ListOpts{IncludeRevoked: true}, path)
	if err != nil || len(records) != 1 {
		t.Fatalf("token list: %v, count %d", err, len(records))
	}
	rec := records[0]
	if !rec.LLMSession || rec.Kind != "agent" {
		t.Errorf("LLM child received token marked llm=%v kind=%q", rec.LLMSession, rec.Kind)
	}
	if rec.MaxUses != sessionMaxUses {
		t.Errorf("token uses = %d, want %d", rec.MaxUses, sessionMaxUses)
	}
	if !rec.Revoked {
		t.Error("token remains active after child exits")
	}
}

func TestSessionTokenDefaultsAndScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	tmpl := registry.ConnectionTemplate{
		Provider:       "audit",
		GatewayActions: []registry.GatewayAction{{Name: "read_one"}, {Name: "write_one"}},
	}
	key := make([]byte, 32)
	_, revoke, err := sessionToken(key, path, "actor", sessionCapabilities(tmpl, "inject"), 0)
	if err != nil {
		t.Fatal(err)
	}
	records, err := token.List(token.ListOpts{}, path)
	if err != nil || len(records) != 1 {
		t.Fatalf("list: %v %d", err, len(records))
	}
	rec := records[0]
	if got := rec.ExpiresAt.Sub(rec.IssuedAt); got != 10*time.Minute {
		t.Errorf("default lifetime %v, want 10m", got)
	}
	if len(rec.Capabilities) != 2 || rec.Capabilities[0] != "audit.read_one" || rec.Capabilities[1] != "audit.write_one" {
		t.Errorf("capabilities = %v, want the template's declared actions", rec.Capabilities)
	}
	revoke()
	if left, _ := token.List(token.ListOpts{}, path); len(left) != 0 {
		t.Error("token still active after revoke")
	}
}
