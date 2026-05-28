// Package grant_test: FIND-001/S8-12 isolation tests.
package grant_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/grant"
)

// TestLLMSession_GrantIssuedUnderCLAUDE_CODE tests that a grant created when
// CLAUDE_CODE=1 has IssuedFromLLMSession=true.
func TestLLMSession_GrantIssuedUnderCLAUDE_CODE(t *testing.T) {
	dir := t.TempDir()
	llmEnv := func(k string) string {
		if k == "KEYLATCH_CONFIG_DIR" {
			return dir
		}
		if k == "CLAUDE_CODE" {
			return "1"
		}
		return ""
	}

	g, err := grant.Create(context.Background(), grant.GrantSpec{
		Actor:      "claude-code",
		Connection: "openrouter:dev",
		Capability: "inject",
		TTL:        time.Hour,
	}, llmEnv)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !g.IssuedFromLLMSession {
		t.Error("FIND-001: IssuedFromLLMSession must be true when CLAUDE_CODE=1")
	}
}

// TestLLMSession_ReadCapabilityDenied ensures that Find returns false for
// read-class capabilities on LLM-issued grants (S8-12).
func TestLLMSession_ReadCapabilityDenied(t *testing.T) {
	dir := t.TempDir()
	llmEnv := func(k string) string {
		if k == "KEYLATCH_CONFIG_DIR" {
			return dir
		}
		if k == "CLAUDE_CODE" {
			return "1"
		}
		return ""
	}
	grantPath := filepath.Join(dir, "grants.json")
	ctx := context.Background()

	g, err := grant.Create(ctx, grant.GrantSpec{
		Actor:      "claude-code",
		Connection: "openrouter:dev",
		Capability: "inject",
		TTL:        time.Hour,
	}, llmEnv)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	readCaps := []string{
		"read",
		"export",
		"credentials.reveal",
		"db.dump",
		"secrets.vault.reveal",
	}
	for _, cap := range readCaps {
		found, ok := grant.Find(ctx, grantPath, grant.FindRequest{
			Actor:      g.Actor,
			Connection: g.Connection,
			Capability: cap,
		})
		if ok || found != nil {
			t.Errorf("S8-12: Find(%q) should return (nil, false) for LLM-issued grant", cap)
		}
	}
}

// TestLLMSession_NonReadCapabilityAllowed ensures Find succeeds for non-read
// capabilities on LLM-issued grants.
func TestLLMSession_NonReadCapabilityAllowed(t *testing.T) {
	dir := t.TempDir()
	llmEnv := func(k string) string {
		if k == "KEYLATCH_CONFIG_DIR" {
			return dir
		}
		if k == "CLAUDE_CODE" {
			return "1"
		}
		return ""
	}
	grantPath := filepath.Join(dir, "grants.json")
	ctx := context.Background()

	g, err := grant.Create(ctx, grant.GrantSpec{
		Actor:      "claude-code",
		Connection: "openrouter:dev",
		Capability: "inject",
		TTL:        time.Hour,
	}, llmEnv)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	found, ok := grant.Find(ctx, grantPath, grant.FindRequest{
		Actor:      g.Actor,
		Connection: g.Connection,
		Capability: "inject",
	})
	if !ok || found == nil {
		t.Error("Find(inject) should succeed for LLM-issued grant with non-read capability")
	}
}
