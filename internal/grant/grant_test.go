package grant_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/grant"
)

// canaryKey is the Phase 8 canary value that must never appear in grant output.
const canaryKey = "KEYLATCH_CANARY_PHASE8_0xDEADBEEF"

// tempEnv returns a Lookup that uses a temp dir for all keylatch paths.
func tempEnv(t *testing.T) func(string) string {
	t.Helper()
	dir := t.TempDir()
	return func(k string) string {
		switch k {
		case "KEYLATCH_CONFIG_DIR":
			return dir
		case "KEYLATCH_GRANTS_PATH":
			return filepath.Join(dir, "grants.json")
		case "KEYLATCH_GRANTS_DIR":
			return filepath.Join(dir, "grants")
		case "KEYLATCH_GRANT_ACCESSOR_KEY_PATH":
			return filepath.Join(dir, "grant-accessor.key")
		}
		return ""
	}
}

func TestCreate_Basic(t *testing.T) {
	env := tempEnv(t)
	ctx := context.Background()

	spec := grant.GrantSpec{
		Actor:      "human-shell",
		Connection: "openrouter:dev",
		Capability: "inject",
		TTL:        1 * time.Hour,
	}

	g, err := grant.Create(ctx, spec, env)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if g.ID == "" {
		t.Error("ID is empty")
	}
	if g.Accessor == "" {
		t.Error("Accessor is empty")
	}
	if g.Actor != "human-shell" {
		t.Errorf("Actor = %q, want human-shell", g.Actor)
	}
	if g.ExpiresAt.IsZero() {
		t.Error("ExpiresAt is zero")
	}
	if g.IssuedFromLLMSession {
		t.Error("IssuedFromLLMSession should be false for non-LLM env")
	}
}

func TestCreate_IDUnique(t *testing.T) {
	env := tempEnv(t)
	ctx := context.Background()
	spec := grant.GrantSpec{Actor: "human-shell", Connection: "a:b", Capability: "inject", TTL: time.Hour}

	g1, _ := grant.Create(ctx, spec, env)
	g2, _ := grant.Create(ctx, spec, env)
	if g1.ID == g2.ID {
		t.Error("Grant IDs must be unique")
	}
}

func TestCreate_SetsIssuedFromLLMSession(t *testing.T) {
	dir := t.TempDir()
	env := func(k string) string {
		switch k {
		case "KEYLATCH_CONFIG_DIR":
			return dir
		case "CLAUDE_CODE":
			return "1"
		}
		return ""
	}

	g, err := grant.Create(context.Background(), grant.GrantSpec{
		Actor:      "claude-code",
		Connection: "openrouter:dev",
		Capability: "inject",
		TTL:        30 * time.Minute,
	}, env)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !g.IssuedFromLLMSession {
		t.Error("IssuedFromLLMSession should be true when CLAUDE_CODE=1")
	}
}

func TestList_Lifecycle(t *testing.T) {
	env := tempEnv(t)
	ctx := context.Background()
	grantPath := env("KEYLATCH_GRANTS_PATH")

	// Create two grants.
	for i := 0; i < 2; i++ {
		_, err := grant.Create(ctx, grant.GrantSpec{
			Actor:      "human-shell",
			Connection: "openrouter:dev",
			Capability: "inject",
			TTL:        1 * time.Hour,
		}, env)
		if err != nil {
			t.Fatalf("Create[%d]: %v", i, err)
		}
	}

	gs, err := grant.List(ctx, grantPath, grant.ListOpts{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(gs) != 2 {
		t.Errorf("List returned %d grants, want 2", len(gs))
	}
}

func TestRevoke_And_Cascade(t *testing.T) {
	env := tempEnv(t)
	ctx := context.Background()
	grantPath := env("KEYLATCH_GRANTS_PATH")

	parent, err := grant.Create(ctx, grant.GrantSpec{
		Actor:      "human-shell",
		Connection: "openrouter:dev",
		Capability: "inject",
		TTL:        1 * time.Hour,
	}, env)
	if err != nil {
		t.Fatalf("Create parent: %v", err)
	}

	// Revoke parent.
	if err := grant.Revoke(ctx, grantPath, parent.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// List with IncludeRevoked=true: parent should be revoked.
	all, err := grant.List(ctx, grantPath, grant.ListOpts{IncludeRevoked: true})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, g := range all {
		if g.ID == parent.ID && !g.Revoked {
			t.Errorf("grant %s should be revoked", g.ID)
		}
	}

	// List without IncludeRevoked=false: revoked grant should not appear.
	active, _ := grant.List(ctx, grantPath, grant.ListOpts{})
	for _, g := range active {
		if g.ID == parent.ID {
			t.Errorf("revoked grant %s appeared in active list", g.ID)
		}
	}
}

func TestFind_Expiry(t *testing.T) {
	env := tempEnv(t)
	ctx := context.Background()
	grantPath := env("KEYLATCH_GRANTS_PATH")

	// Create grant with very short TTL.
	g, err := grant.Create(ctx, grant.GrantSpec{
		Actor:      "human-shell",
		Connection: "test:conn",
		Capability: "inject",
		TTL:        1 * time.Millisecond,
	}, env)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	time.Sleep(5 * time.Millisecond) // let it expire

	found, ok := grant.Find(ctx, grantPath, grant.FindRequest{
		Actor:      g.Actor,
		Connection: g.Connection,
		Capability: g.Capability,
	})
	if ok || found != nil {
		t.Error("Find should return nil for expired grant (S8-3)")
	}
}

func TestFind_RevokedNotReturned(t *testing.T) {
	env := tempEnv(t)
	ctx := context.Background()
	grantPath := env("KEYLATCH_GRANTS_PATH")

	g, err := grant.Create(ctx, grant.GrantSpec{
		Actor:      "human-shell",
		Connection: "test:conn",
		Capability: "inject",
		TTL:        1 * time.Hour,
	}, env)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := grant.Revoke(ctx, grantPath, g.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	found, ok := grant.Find(ctx, grantPath, grant.FindRequest{
		Actor:      g.Actor,
		Connection: g.Connection,
		Capability: g.Capability,
	})
	if ok || found != nil {
		t.Error("Find should return nil for revoked grant (S8-4)")
	}
}

// TestFind_S8_12_LLMGrantDeniedForReadClass verifies that grants issued
// from an LLM session are denied for read-class capabilities (FIND-001/S8-12).
func TestFind_S8_12_LLMGrantDeniedForReadClass(t *testing.T) {
	dir := t.TempDir()
	llmEnv := func(k string) string {
		switch k {
		case "KEYLATCH_CONFIG_DIR":
			return dir
		case "CLAUDE_CODE":
			return "1"
		}
		return ""
	}
	ctx := context.Background()
	grantPath := filepath.Join(dir, "grants.json")

	g, err := grant.Create(ctx, grant.GrantSpec{
		Actor:      "claude-code",
		Connection: "openrouter:dev",
		Capability: "read",
		TTL:        1 * time.Hour,
	}, llmEnv)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !g.IssuedFromLLMSession {
		t.Fatal("expected IssuedFromLLMSession=true")
	}

	readClassCaps := []string{"read", "export", "db.credentials.reveal", "db.dump"}
	for _, cap := range readClassCaps {
		found, ok := grant.Find(ctx, grantPath, grant.FindRequest{
			Actor:      g.Actor,
			Connection: g.Connection,
			Capability: cap,
		})
		if ok || found != nil {
			t.Errorf("Find with read-class cap %q should return nil for LLM-issued grant (S8-12)", cap)
		}
	}

	// Non-read capability should still match.
	g2, err := grant.Create(ctx, grant.GrantSpec{
		Actor:      "claude-code",
		Connection: "openrouter:dev",
		Capability: "inject",
		TTL:        1 * time.Hour,
	}, llmEnv)
	if err != nil {
		t.Fatalf("Create inject grant: %v", err)
	}
	found, ok := grant.Find(ctx, grantPath, grant.FindRequest{
		Actor:      g2.Actor,
		Connection: g2.Connection,
		Capability: "inject",
	})
	if !ok || found == nil {
		t.Error("Find with non-read-class cap should succeed for LLM-issued grant")
	}
}

func TestGrantFileModeIs0600(t *testing.T) {
	env := tempEnv(t)
	ctx := context.Background()

	_, err := grant.Create(ctx, grant.GrantSpec{
		Actor:      "human-shell",
		Connection: "test:conn",
		Capability: "inject",
		TTL:        1 * time.Hour,
	}, env)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	grantPath := env("KEYLATCH_GRANTS_PATH")
	info, err := os.Stat(grantPath)
	if err != nil {
		t.Fatalf("Stat grants file: %v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("grants.json permissions = %04o, want 0600", perm)
	}
}

func TestRevoke_NotFound(t *testing.T) {
	env := tempEnv(t)
	ctx := context.Background()
	grantPath := env("KEYLATCH_GRANTS_PATH")

	// Create a grant so the file exists.
	_, err := grant.Create(ctx, grant.GrantSpec{
		Actor: "human-shell", Connection: "a:b", Capability: "inject", TTL: time.Hour,
	}, env)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := grant.Revoke(ctx, grantPath, "nonexistent-id"); err == nil {
		t.Error("Revoke of nonexistent ID should return an error")
	}
}

// TestCanary verifies the canary value never appears in grant output fields.
func TestCanary(t *testing.T) {
	env := tempEnv(t)
	ctx := context.Background()

	g, err := grant.Create(ctx, grant.GrantSpec{
		Actor:      "human-shell",
		Connection: "fixture:dev",
		Capability: "inject",
		TTL:        1 * time.Hour,
	}, env)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// The canary must not appear as the grant Accessor or ID.
	if g.Accessor == canaryKey {
		t.Error("Accessor must not equal raw canary key")
	}
	if g.ID == canaryKey {
		t.Error("ID must not equal raw canary key")
	}
}
