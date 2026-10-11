package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/testutil"
)

const ccTeamID = "cc-team"

// ccTeam writes a team with an owner, an admin, a developer and a viewer to
// an isolated KEYLATCH_TEAM_DIR and returns the team.
func ccTeam(t *testing.T) *team.Team {
	t.Helper()
	testutil.ClearLLMSessionEnv(t)
	t.Setenv("KEYLATCH_TEAM_DIR", t.TempDir())
	joined := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	tm := &team.Team{ID: ccTeamID, Name: "CC Team", SyncRepoURL: "file:///srv/cc.git"}
	for _, m := range []struct {
		id   string
		role team.Role
	}{
		{"m-owner", team.RoleOwner},
		{"m-admin", team.RoleAdmin},
		{"m-dev", team.RoleDeveloper},
		{"m-view", team.RoleViewer},
	} {
		tm.Members = append(tm.Members, team.Member{
			ID:       m.id,
			HMAC:     team.HMACValue(ccTeamID, m.id+"@example.com"),
			Role:     m.role,
			Status:   team.MemberActive,
			JoinedAt: joined,
		})
	}
	if err := team.Save(context.Background(), tm); err != nil {
		t.Fatalf("save team: %v", err)
	}
	return tm
}

func ccLoadTeam(t *testing.T) *team.Team {
	t.Helper()
	tm, err := team.Load(context.Background())
	if err != nil {
		t.Fatalf("load team: %v", err)
	}
	return tm
}

func ccMember(t *testing.T, tm *team.Team, id string) team.Member {
	t.Helper()
	m, err := team.FindMember(tm, id)
	if err != nil {
		t.Fatalf("member %s: %v", id, err)
	}
	return m
}

func TestCCTeamList_TextIsValueFree(t *testing.T) {
	ccTeam(t)
	out, _, err := ccRun(t, "", "team", "list")
	if err != nil {
		t.Fatalf("team list: %v", err)
	}
	if !strings.HasPrefix(out, "Team: cc-team (4 members)\n") {
		t.Fatalf("header = %q", out)
	}
	for _, want := range []string{"m-owner  role=owner", "status=active", "joined=2026-01-02T03:04:05Z", "hmac=" + team.HMACValue(ccTeamID, "m-dev@example.com")} {
		if !strings.Contains(out, want) {
			t.Errorf("list missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "@example.com") {
		t.Fatalf("raw email printed: %s", out)
	}
}

func TestCCTeamInvite_CreatesSignedBundle(t *testing.T) {
	ccTeam(t)
	actAs(t, "m-admin")
	hmac := team.HMACValue(ccTeamID, "new@example.com")

	out, _, err := ccRun(t, "", "team", "invite", "--email-hmac", hmac, "--role", "", "--json")
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	var res struct {
		Status    string `json:"status"`
		EmailHMAC string `json:"email_hmac"`
		Role      string `json:"role"`
		Bundle    []byte `json:"bundle"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("json: %v (%q)", err, out)
	}
	if res.Status != "invited" || res.EmailHMAC != hmac || res.Role != "developer" {
		t.Fatalf("invite = %+v", res)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimRight(string(res.Bundle), "\x00"))
	if err != nil {
		t.Fatalf("bundle not base64: %v", err)
	}
	var b team.InviteBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("bundle json: %v", err)
	}
	if b.TeamID != ccTeamID || b.MemberHMAC != hmac || b.Role != team.RoleDeveloper || b.Signature == "" || !b.ExpiresAt.After(b.IssuedAt) {
		t.Fatalf("bundle = %+v", b)
	}

	text, _, err := ccRun(t, "", "team", "invite", "--email-hmac", hmac, "--role", "viewer")
	if err != nil {
		t.Fatalf("invite text: %v", err)
	}
	if !strings.HasPrefix(text, "Invite bundle created for role=viewer.\nBundle: ") {
		t.Fatalf("text = %q", text)
	}
}

func TestCCTeamInvite_NoTeamConfigured(t *testing.T) {
	t.Setenv("KEYLATCH_TEAM_DIR", t.TempDir())
	_, _, err := ccRun(t, "", "team", "invite", "--email-hmac", "abc")
	if err == nil || !strings.HasPrefix(err.Error(), "team invite:") {
		t.Fatalf("err = %v", err)
	}
}

func TestCCTeamMutations_RequireAdminCaller(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		prefix  string
		missing string
	}{
		{"remove", []string{"team", "remove", "--id", "m-dev"}, "team remove:", "--id is required"},
		{"transfer", []string{"team", "transfer", "--to", "m-dev"}, "team transfer:", "--to is required"},
		{"role", []string{"team", "role", "--id", "m-dev", "--role", "viewer"}, "team role:", "--id and --role are required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ccTeam(t)
			withInteractiveStdin(t, true)

			_, _, err := ccRun(t, "", tc.args[:2]...)
			if err == nil || !strings.Contains(err.Error(), tc.missing) {
				t.Fatalf("missing flag err = %v", err)
			}

			_, _, err = ccRun(t, "", tc.args...)
			if err == nil || !strings.Contains(err.Error(), "governance unavailable in this build") {
				t.Fatalf("anonymous caller err = %v", err)
			}

			actAs(t, "m-ghost")
			_, _, err = ccRun(t, "", tc.args...)
			if err == nil || !errors.Is(err, team.ErrMemberNotFound) {
				t.Fatalf("unknown caller err = %v", err)
			}

			for _, low := range []string{"m-dev", "m-view"} {
				actAs(t, low)
				_, _, err = ccRun(t, "", tc.args...)
				if err == nil || (!errors.Is(err, team.ErrRoleInsufficient) && !strings.Contains(err.Error(), "only the current team owner")) || !strings.HasPrefix(err.Error(), tc.prefix) {
					t.Fatalf("caller %s err = %v", low, err)
				}
			}

			after := ccLoadTeam(t)
			dev := ccMember(t, after, "m-dev")
			if dev.Role != team.RoleDeveloper || dev.Status != team.MemberActive {
				t.Fatalf("denied mutation changed state: %+v", dev)
			}
		})
	}
}

func TestCCTeamRemove_ByAdmin(t *testing.T) {
	ccTeam(t)
	actAs(t, "m-admin")

	var rotated []string
	old := team.OnRotateSharedSecrets
	team.OnRotateSharedSecrets = func(_ context.Context, _ *team.Team, id string) error {
		rotated = append(rotated, id)
		return nil
	}
	t.Cleanup(func() { team.OnRotateSharedSecrets = old })

	out, _, err := ccRun(t, "", "team", "remove", "--id", "m-dev")
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if out != "Member m-dev removed. Shared secrets rotated.\n" {
		t.Fatalf("out = %q", out)
	}
	if len(rotated) != 1 || rotated[0] != "m-dev" {
		t.Fatalf("rotation callback = %v", rotated)
	}
	if got := ccMember(t, ccLoadTeam(t), "m-dev").Status; got != team.MemberRemoved {
		t.Fatalf("status = %s", got)
	}

	jsonOut, _, err := ccRun(t, "", "team", "remove", "--id", "m-view", "--json")
	if err != nil {
		t.Fatalf("remove --json: %v", err)
	}
	var res map[string]string
	if err := json.Unmarshal([]byte(jsonOut), &res); err != nil || res["status"] != "removed" || res["member_id"] != "m-view" {
		t.Fatalf("json = %q (%v)", jsonOut, err)
	}

	_, _, err = ccRun(t, "", "team", "remove", "--id", "m-ghost")
	if err == nil || !errors.Is(err, team.ErrMemberNotFound) {
		t.Fatalf("remove unknown err = %v", err)
	}
}

func TestCCTeamTransfer_ByOwner(t *testing.T) {
	ccTeam(t)
	withInteractiveStdin(t, true)
	actAs(t, "m-owner")

	out, _, err := ccRun(t, "", "team", "transfer", "--to", "m-dev")
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}
	if out != "Ownership transferred to m-dev.\n" {
		t.Fatalf("out = %q", out)
	}
	after := ccLoadTeam(t)
	if ccMember(t, after, "m-dev").Role != team.RoleOwner || ccMember(t, after, "m-owner").Role != team.RoleAdmin {
		t.Fatalf("roles after transfer: %+v", after.Members)
	}

	actAs(t, "m-dev")
	jsonOut, _, err := ccRun(t, "", "team", "transfer", "--to", "m-owner", "--json")
	if err != nil {
		t.Fatalf("transfer --json: %v", err)
	}
	var res map[string]string
	if err := json.Unmarshal([]byte(jsonOut), &res); err != nil || res["status"] != "transferred" || res["to_id"] != "m-owner" {
		t.Fatalf("json = %q (%v)", jsonOut, err)
	}

	_, _, err = ccRun(t, "", "team", "transfer", "--to", "m-ghost")
	if err == nil || !errors.Is(err, team.ErrMemberNotFound) {
		t.Fatalf("transfer to unknown err = %v", err)
	}
}

func TestCCTeamRole_ByAdmin(t *testing.T) {
	ccTeam(t)
	actAs(t, "m-admin")

	out, _, err := ccRun(t, "", "team", "role", "--id", "m-view", "--role", "developer")
	if err != nil {
		t.Fatalf("role: %v", err)
	}
	if out != "Member m-view role updated to developer.\n" {
		t.Fatalf("out = %q", out)
	}
	if got := ccMember(t, ccLoadTeam(t), "m-view").Role; got != team.RoleDeveloper {
		t.Fatalf("role persisted = %s", got)
	}

	jsonOut, _, err := ccRun(t, "", "team", "role", "--id", "m-dev", "--role", "viewer", "--json")
	if err != nil {
		t.Fatalf("role --json: %v", err)
	}
	var res map[string]string
	if err := json.Unmarshal([]byte(jsonOut), &res); err != nil || res["status"] != "updated" || res["new_role"] != "viewer" {
		t.Fatalf("json = %q (%v)", jsonOut, err)
	}

	_, _, err = ccRun(t, "", "team", "role", "--id", "m-ghost", "--role", "viewer")
	if err == nil || !errors.Is(err, team.ErrMemberNotFound) {
		t.Fatalf("role unknown err = %v", err)
	}
}

func TestCCTeamHashEmail(t *testing.T) {
	ccTeam(t)
	out, _, err := ccRun(t, "", "team", "hash-email", "alice@example.com")
	if err != nil {
		t.Fatalf("hash-email: %v", err)
	}
	want := "SHA256-HMAC: " + team.HMACValue(ccTeamID, "alice@example.com") + "  (use this value for --email-hmac)\n"
	if out != want {
		t.Fatalf("out = %q, want %q", out, want)
	}
}

func TestCCSaveTeam_PersistsChanges(t *testing.T) {
	tm := ccTeam(t)
	tm.Name = "Renamed"
	if err := team.Save(context.Background(), tm); err != nil {
		t.Fatalf("saveTeam: %v", err)
	}
	if got := ccLoadTeam(t).Name; got != "Renamed" {
		t.Fatalf("name = %q", got)
	}
}
