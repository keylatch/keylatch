package simulate_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/team/bundlesig"
	"github.com/keylatch/keylatch/internal/team/orgpolicy"
	"github.com/keylatch/keylatch/internal/team/simulate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mxNoOrgPolicy(t *testing.T) {
	t.Helper()
	t.Setenv("KEYLATCH_ORG_POLICY_DIR", t.TempDir())
	orgpolicy.ResetForTest()
	t.Cleanup(orgpolicy.ResetForTest)
}

func TestSimulate_RiskHeuristics(t *testing.T) {
	mxNoOrgPolicy(t)
	ctx := context.Background()
	cases := []struct {
		capability, env string
		role            team.Role
		decision        string
		levels          []string
	}{
		{"inject", "development", team.RoleDeveloper, "allow", nil},
		{"db.write", "production", team.RoleDeveloper, "approval_required", []string{"high"}},
		{"secrets.reveal", "production", team.RoleDeveloper, "allow", []string{"medium"}},
		{"delete", "staging", team.RoleViewer, "approval_required", []string{"critical"}},
		{"rotate", "production", team.RoleViewer, "approval_required", []string{"high", "critical"}},
	}
	for _, tc := range cases {
		r, err := simulate.Simulate(ctx, tc.capability, tc.env, newMember(tc.role))
		require.NoError(t, err)
		assert.Equal(t, tc.decision, r.Decision, tc.capability)
		var levels []string
		for _, risk := range r.Risks {
			levels = append(levels, risk.Level)
		}
		assert.Equal(t, tc.levels, levels, tc.capability)
		if tc.decision == "approval_required" {
			assert.Contains(t, r.Reason, tc.capability)
		}
	}
}

func TestSimulate_OrgRequiresApproval(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_ORG_POLICY_DIR", dir)
	orgpolicy.ResetForTest()
	t.Cleanup(orgpolicy.ResetForTest)
	b := &orgpolicy.OrgBundle{
		SchemaVersion: "1", BundleID: "b", Version: 1, TeamID: "t", Issuer: "i",
		IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour),
		AllowedEnvelope: orgpolicy.AllowedEnvelope{RequireApproval: []string{"deploy"}},
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	orgpolicy.SignBundle(b, priv)
	data, err := json.Marshal(b)
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), "b.json")
	require.NoError(t, os.WriteFile(p, data, 0o600))
	require.NoError(t, orgpolicy.Install(context.Background(), p, bundlesig.EncodePublicKey(pub)))

	r, err := simulate.Simulate(context.Background(), "deploy", "", newMember(team.RoleAdmin))
	require.NoError(t, err)
	assert.Equal(t, "approval_required", r.Decision)
	assert.True(t, r.OrgOverride)
	assert.Contains(t, r.Reason, "approval required by org policy")
}

func TestExplain_FullResult(t *testing.T) {
	out := simulate.Explain(&simulate.SimResult{
		Decision:    "deny",
		Reason:      "baseline",
		OrgOverride: true,
		Risks:       []simulate.Risk{{Level: "high", Message: "danger"}},
	})
	for _, want := range []string{"Decision: deny\n", "Reason: baseline\n", "Org policy overrode local rule", "Risks:\n", " [high] danger\n"} {
		assert.Contains(t, out, want)
	}
	assert.NotContains(t, out, "Matched Rule")

	minimal := simulate.Explain(&simulate.SimResult{Decision: "allow"})
	assert.Equal(t, 2, strings.Count(minimal, "\n"))
}
