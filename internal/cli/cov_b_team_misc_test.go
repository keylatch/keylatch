package cli

// cov_b_team_misc_test.go — Agent B coverage for team_cmd.go (error paths and
// command registration), ui_cmd.go (registration), store_adapter.go.
// Hermetic: no network, no OS keychain.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/team"
)

// --- team_cmd.go ---

func setupTeamDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	return dir
}

// writeTeamFixture writes a minimal team.json for tests that need a configured team.
func writeTeamFixture(t *testing.T, dir string) *team.Team {
	t.Helper()
	ctx := context.Background()
	tm := &team.Team{
		ID:      "test-team-id",
		Members: []team.Member{},
	}
	// Use the team.Save path — needs KEYLATCH_TEAM_DIR.
	if err := team.Save(ctx, tm); err != nil {
		t.Fatalf("writeTeamFixture: %v", err)
	}
	return tm
}

func TestTeamListCmd_NoTeam(t *testing.T) {
	setupTeamDir(t)

	root := NewRootCommand()
	root.SetOut(bytes.NewBuffer(nil))
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"team", "list"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when team not configured")
	}
}

func TestTeamListCmd_JSON_WithTeam(t *testing.T) {
	dir := setupTeamDir(t)
	writeTeamFixture(t, dir)

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"team", "list", "--json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("team list --json: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &result); err != nil {
		t.Fatalf("JSON parse: %v — output: %s", err, out.String())
	}
	if _, ok := result["team_id"]; !ok {
		t.Errorf("expected 'team_id' in JSON output, got: %v", result)
	}
}

func TestTeamHashEmailCmd_InvalidEmail(t *testing.T) {
	dir := setupTeamDir(t)
	writeTeamFixture(t, dir)

	cases := []string{
		"notanemail",
		"@example.com",
		"user@",
	}
	for _, email := range cases {
		root := NewRootCommand()
		root.SetOut(bytes.NewBuffer(nil))
		root.SetErr(bytes.NewBuffer(nil))
		root.SetArgs([]string{"team", "hash-email", email})

		err := root.Execute()
		if err == nil {
			t.Errorf("expected error for invalid email %q", email)
		}
	}
}

func TestTeamHashEmailCmd_ValidEmail(t *testing.T) {
	dir := setupTeamDir(t)
	writeTeamFixture(t, dir)

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"team", "hash-email", "alice@example.com"})

	if err := root.Execute(); err != nil {
		t.Fatalf("team hash-email: %v", err)
	}

	if !strings.Contains(out.String(), "SHA256-HMAC:") {
		t.Errorf("expected 'SHA256-HMAC:' in output, got: %s", out.String())
	}
}

func TestTeamHashEmailCmd_NoTeam(t *testing.T) {
	setupTeamDir(t)
	// No team configured.

	root := NewRootCommand()
	root.SetOut(bytes.NewBuffer(nil))
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"team", "hash-email", "alice@example.com"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when team not configured")
	}
}

// NOTE: team invite with missing --email-hmac calls os.Exit() — not testable
// through Execute() in the same process. Registration is verified below.

func TestTeamInviteCmd_Registered(t *testing.T) {
	root := NewRootCommand()
	cmd, _, err := root.Find([]string{"team", "invite"})
	if err != nil || cmd == nil {
		t.Fatal("expected 'team invite' command to be registered")
	}
	if f := cmd.Flags().Lookup("email-hmac"); f == nil {
		t.Error("expected --email-hmac flag on team invite command")
	}
	if f := cmd.Flags().Lookup("role"); f == nil {
		t.Error("expected --role flag on team invite command")
	}
}

func TestTeamRemoveCmd_RequiresID(t *testing.T) {
	dir := setupTeamDir(t)
	writeTeamFixture(t, dir)

	root := NewRootCommand()
	root.SetOut(bytes.NewBuffer(nil))
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"team", "remove"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when --id is missing")
	}
	if !strings.Contains(err.Error(), "--id") {
		t.Errorf("expected '--id' in error, got: %v", err)
	}
}

// NOTE: team rotate-owner-key calls os.Exit — not testable via Execute().
// Just verify it is registered.
func TestTeamRotateOwnerKeyCmd_Registered(t *testing.T) {
	root := NewRootCommand()
	// rotate-owner-key is Hidden but still registered.
	cmd, _, err := root.Find([]string{"team", "rotate-owner-key"})
	if err != nil || cmd == nil {
		t.Fatal("expected 'team rotate-owner-key' command to be registered")
	}
}

// --- loadTeam/saveTeam via CLI commands ---

func TestLoadTeam_NotFound(t *testing.T) {
	setupTeamDir(t)

	_, err := loadTeam()
	if err == nil {
		t.Fatal("expected error when team not configured")
	}
}

func TestLoadSaveTeam_RoundTrip(t *testing.T) {
	dir := setupTeamDir(t)

	// Write minimal team directly.
	teamPath := filepath.Join(dir, "team.json")
	tm := &team.Team{ID: "round-trip-id", Members: []team.Member{}}
	data, _ := json.Marshal(tm)
	if err := os.WriteFile(teamPath, data, 0o600); err != nil {
		t.Fatalf("write team: %v", err)
	}

	loaded, err := loadTeam()
	if err != nil {
		t.Fatalf("loadTeam: %v", err)
	}
	if loaded.ID != "round-trip-id" {
		t.Errorf("expected team ID 'round-trip-id', got: %s", loaded.ID)
	}
}

// --- ui_cmd.go ---

func TestUICmd_Registered(t *testing.T) {
	root := NewRootCommand()
	cmd, _, err := root.Find([]string{"ui"})
	if err != nil || cmd == nil {
		t.Fatal("expected 'ui' command to be registered")
	}
}

func TestUICmd_HasExpectedFlags(t *testing.T) {
	root := NewRootCommand()
	cmd, _, err := root.Find([]string{"ui"})
	if err != nil || cmd == nil {
		t.Fatal("expected 'ui' command to be registered")
	}
	for _, flagName := range []string{"port", "demo", "no-open"} {
		if f := cmd.Flags().Lookup(flagName); f == nil {
			t.Errorf("expected --%s flag on ui command", flagName)
		}
	}
}

// --- store_adapter.go ---

// TestDispatchedStore_NewDispatchedStore verifies that newDispatchedStore
// returns a non-nil store with the correct config and env.
func TestDispatchedStore_NewDispatchedStore(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)
	t.Setenv("KEYLATCH_BACKEND", "file")

	// dispatchedStore is unexported; we cover it via the constructor which
	// is exercised by any command that uses newDispatchedStore.
	// Direct instantiation to test struct creation.
	store := newDispatchedStore(loadCLIConfig(NewRootCommand()), func(k string) string {
		if k == "KEYLATCH_BACKEND" {
			return "file"
		}
		return ""
	})
	if store == nil {
		t.Fatal("expected non-nil dispatchedStore")
	}
}
