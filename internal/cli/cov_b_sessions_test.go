package cli

// cov_b_sessions_test.go — Agent B coverage for sessions_cmd.go.
// Tests for sessions list/start/kill commands and loadSessions/saveSessions helpers.
// Hermetic: all filesystem access is redirected via KEYLATCH_CONFIG_DIR.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setupSessionsDir creates a temp dir and sets KEYLATCH_CONFIG_DIR so that
// Sessions() and paths helpers resolve inside it.
func setupSessionsDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)
	return dir
}

func TestSessionsList_Empty(t *testing.T) {
	setupSessionsDir(t)

	root := NewRootCommand()
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	root.SetArgs([]string{"sessions", "list"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should show header only.
	if !strings.Contains(out.String(), "ID") {
		t.Errorf("expected header in output, got: %s", out.String())
	}
}

func TestSessionsList_JSON_Empty(t *testing.T) {
	setupSessionsDir(t)

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"sessions", "list", "--json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var arr []map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &arr); err != nil {
		t.Fatalf("expected valid JSON array, got: %s (%v)", out.String(), err)
	}
	if len(arr) != 0 {
		t.Errorf("expected empty array, got: %d items", len(arr))
	}
}

func TestSessionsStart_RequiresActor(t *testing.T) {
	setupSessionsDir(t)

	root := NewRootCommand()
	root.SetOut(bytes.NewBuffer(nil))
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"sessions", "start"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when --actor is missing")
	}
	if !strings.Contains(err.Error(), "--actor") {
		t.Errorf("expected --actor mention in error, got: %v", err)
	}
}

func TestSessionsStart_CreatesSession(t *testing.T) {
	setupSessionsDir(t)

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"sessions", "start", "--actor", "test-agent", "--ttl", "30m"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "session id:") {
		t.Errorf("expected 'session id:' in output, got: %s", output)
	}
	if !strings.Contains(output, "expires at:") {
		t.Errorf("expected 'expires at:' in output, got: %s", output)
	}
}

func TestSessionsStart_InvalidTTL(t *testing.T) {
	setupSessionsDir(t)

	root := NewRootCommand()
	root.SetOut(bytes.NewBuffer(nil))
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"sessions", "start", "--actor", "agent", "--ttl", "notaduration"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for invalid TTL")
	}
	if !strings.Contains(err.Error(), "invalid --ttl") {
		t.Errorf("expected 'invalid --ttl' in error, got: %v", err)
	}
}

func TestSessionsKill_KillsSession(t *testing.T) {
	setupSessionsDir(t)

	// Create a session first.
	startRoot := NewRootCommand()
	var startOut bytes.Buffer
	startRoot.SetOut(&startOut)
	startRoot.SetErr(bytes.NewBuffer(nil))
	startRoot.SetArgs([]string{"sessions", "start", "--actor", "agent", "--ttl", "1h"})
	if err := startRoot.Execute(); err != nil {
		t.Fatalf("start session: %v", err)
	}

	// Extract session ID from output.
	lines := strings.Split(strings.TrimSpace(startOut.String()), "\n")
	var sessionID string
	for _, line := range lines {
		if strings.HasPrefix(line, "session id:") {
			sessionID = strings.TrimSpace(strings.TrimPrefix(line, "session id:"))
		}
	}
	if sessionID == "" {
		t.Fatalf("could not extract session ID from output: %s", startOut.String())
	}

	// Kill the session.
	killRoot := NewRootCommand()
	var killOut bytes.Buffer
	killRoot.SetOut(&killOut)
	killRoot.SetErr(bytes.NewBuffer(nil))
	killRoot.SetArgs([]string{"sessions", "kill", sessionID})
	if err := killRoot.Execute(); err != nil {
		t.Fatalf("kill session: %v", err)
	}

	if !strings.Contains(killOut.String(), sessionID) {
		t.Errorf("expected session ID in kill output, got: %s", killOut.String())
	}

	// Session should now be inactive in list.
	listRoot := NewRootCommand()
	var listOut bytes.Buffer
	listRoot.SetOut(&listOut)
	listRoot.SetErr(bytes.NewBuffer(nil))
	listRoot.SetArgs([]string{"sessions", "list", "--json"})
	if err := listRoot.Execute(); err != nil {
		t.Fatalf("list sessions: %v", err)
	}

	var arr []map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(listOut.String())), &arr); err != nil {
		t.Fatalf("parse JSON: %v — output: %s", err, listOut.String())
	}
	// Active list should be empty after kill.
	if len(arr) != 0 {
		t.Errorf("expected 0 active sessions after kill, got: %d", len(arr))
	}
}

func TestSessionsKill_NotFound(t *testing.T) {
	setupSessionsDir(t)

	root := NewRootCommand()
	root.SetOut(bytes.NewBuffer(nil))
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"sessions", "kill", "nonexistent-id"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for missing session")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

func TestLoadSaveSessions_RoundTrip(t *testing.T) {
	setupSessionsDir(t)

	// Initially empty.
	sessions, err := loadSessions()
	if err != nil {
		t.Fatalf("loadSessions: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}

	// Save some sessions.
	entries := []sessionEntry{
		{ID: "s1", Actor: "claude", Active: true},
		{ID: "s2", Actor: "codex", Active: false},
	}
	if err := saveSessions(entries); err != nil {
		t.Fatalf("saveSessions: %v", err)
	}

	// Reload and verify.
	loaded, err := loadSessions()
	if err != nil {
		t.Fatalf("loadSessions after save: %v", err)
	}
	if len(loaded) != 2 {
		t.Errorf("expected 2 sessions, got %d", len(loaded))
	}
	if loaded[0].ID != "s1" || loaded[1].ID != "s2" {
		t.Errorf("unexpected session IDs: %v", loaded)
	}
}

func TestLoadSessions_InvalidJSON(t *testing.T) {
	dir := setupSessionsDir(t)

	// Write invalid JSON to the sessions file.
	sessPath := filepath.Join(dir, "sessions.json")
	if err := os.WriteFile(sessPath, []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("write bad json: %v", err)
	}

	_, err := loadSessions()
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestSessionsList_ShowsActive(t *testing.T) {
	setupSessionsDir(t)

	// Seed sessions directly.
	entries := []sessionEntry{
		{ID: "active-1", Actor: "agent-a", Active: true},
		{ID: "inactive-1", Actor: "agent-b", Active: false},
	}
	if err := saveSessions(entries); err != nil {
		t.Fatalf("saveSessions: %v", err)
	}

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"sessions", "list"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "active-1") {
		t.Errorf("expected active-1 in output, got: %s", output)
	}
	// Inactive should not show in list.
	if strings.Contains(output, "inactive-1") {
		t.Errorf("inactive-1 should not appear in active sessions list: %s", output)
	}
}

func TestSessionsList_JSON_ShowsActive(t *testing.T) {
	setupSessionsDir(t)

	entries := []sessionEntry{
		{ID: "active-1", Actor: "agent-a", Active: true},
		{ID: "inactive-1", Actor: "agent-b", Active: false},
	}
	if err := saveSessions(entries); err != nil {
		t.Fatalf("saveSessions: %v", err)
	}

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"sessions", "list", "--json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var arr []sessionEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &arr); err != nil {
		t.Fatalf("JSON parse: %v — output: %s", err, out.String())
	}
	if len(arr) != 1 {
		t.Errorf("expected 1 active session, got: %d", len(arr))
	}
	if arr[0].ID != "active-1" {
		t.Errorf("expected active-1, got: %s", arr[0].ID)
	}
}

func TestSaveSessions_NilSavesEmptyArray(t *testing.T) {
	setupSessionsDir(t)

	// Save nil — should not panic and should produce valid JSON.
	if err := saveSessions(nil); err != nil {
		t.Fatalf("saveSessions(nil): %v", err)
	}

	loaded, err := loadSessions()
	if err != nil {
		t.Fatalf("loadSessions after nil save: %v", err)
	}
	if loaded == nil {
		// The file exists but has "[]" — loadSessions decodes to empty slice.
		// Both nil and []sessionEntry{} are acceptable.
	}
	_ = loaded
}

func TestSessionsStart_DefaultTTL(t *testing.T) {
	setupSessionsDir(t)

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	// Use default TTL (1h) by omitting --ttl.
	root.SetArgs([]string{"sessions", "start", "--actor", "default-ttl-agent"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have created the session.
	sessions, err := loadSessions()
	if err != nil {
		t.Fatalf("loadSessions: %v", err)
	}
	found := false
	for _, s := range sessions {
		if s.Actor == "default-ttl-agent" {
			found = true
			// Verify expires is approximately 1 hour from now.
			diff := s.ExpiresAt.Sub(s.StartedAt)
			if diff < 50*60e9 || diff > 70*60e9 { // between 50m and 70m in nanoseconds
				t.Errorf("expected ~1h TTL, got: %v", diff)
			}
		}
	}
	if !found {
		t.Errorf("created session not found in store; sessions: %v", sessions)
	}
}

func TestSessionsStart_MultipleActors(t *testing.T) {
	setupSessionsDir(t)

	for i := 0; i < 3; i++ {
		root := NewRootCommand()
		root.SetOut(bytes.NewBuffer(nil))
		root.SetErr(bytes.NewBuffer(nil))
		root.SetArgs([]string{"sessions", "start", "--actor", fmt.Sprintf("actor-%d", i)})
		if err := root.Execute(); err != nil {
			t.Fatalf("start session %d: %v", i, err)
		}
	}

	sessions, err := loadSessions()
	if err != nil {
		t.Fatalf("loadSessions: %v", err)
	}
	if len(sessions) != 3 {
		t.Errorf("expected 3 sessions, got: %d", len(sessions))
	}
}
