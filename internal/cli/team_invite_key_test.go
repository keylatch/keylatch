package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/keylatch/keylatch/internal/team"
)

func TestTeamInvitePrintsTeamKeyThatVerifiesTheBundle(t *testing.T) {
	writeRosterFixture(t)
	actAs(t, "owner")

	out := &bytes.Buffer{}
	root := NewRootCommand()
	root.SetOut(out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"team", "invite", "--email-hmac", "alice-hmac", "--role", "viewer", "--json"})
	if err := root.Execute(); err != nil {
		t.Fatalf("team invite: %v", err)
	}

	var got struct {
		Bundle  []byte `json:"bundle"`
		TeamKey string `json:"team_key"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("parse output %q: %v", out, err)
	}
	if got.TeamKey == "" {
		t.Fatal("team invite did not print the team key")
	}

	t.Setenv("KEYLATCH_TEAM_DIR", t.TempDir())
	if _, err := team.Join(context.Background(), got.Bundle, got.TeamKey); err != nil {
		t.Fatalf("Join with the printed team key: %v", err)
	}
}
