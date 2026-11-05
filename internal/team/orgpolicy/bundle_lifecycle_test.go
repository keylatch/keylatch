package orgpolicy_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/team/orgpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mxPolicyDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "org-policy")
	t.Setenv("KEYLATCH_ORG_POLICY_DIR", dir)
	orgpolicy.ResetForTest()
	t.Cleanup(orgpolicy.ResetForTest)
	return dir
}

func mxBundleFile(t *testing.T, b any) string {
	t.Helper()
	data, err := json.Marshal(b)
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), "bundle.json")
	require.NoError(t, os.WriteFile(p, data, 0o600))
	return p
}

func mxSigned(t *testing.T, k orgKey, version int64, expiresIn time.Duration) *orgpolicy.OrgBundle {
	t.Helper()
	b := newTestBundle(version, expiresIn)
	orgpolicy.SignBundle(b, k.priv)
	return b
}

func TestVerify(t *testing.T) {
	ctx := context.Background()
	k := newKey(t)
	good := mxSigned(t, k, 1, time.Hour)
	require.NoError(t, orgpolicy.Verify(ctx, mxBundleFile(t, good), k.pub))

	tampered := *good
	tampered.BaselineDeny = nil
	tampered.AllowedEnvelope.DenyCapabilities = []string{}
	tampered.AllowedEnvelope.MaxScope = "unlimited"
	assert.ErrorIs(t, orgpolicy.Verify(ctx, mxBundleFile(t, tampered), k.pub), orgpolicy.ErrSignatureInvalid)

	assert.ErrorIs(t, orgpolicy.Verify(ctx, mxBundleFile(t, good), newKey(t).pub), orgpolicy.ErrSignatureInvalid, "a different org key")

	expired := mxSigned(t, k, 1, -time.Minute)
	assert.ErrorIs(t, orgpolicy.Verify(ctx, mxBundleFile(t, expired), k.pub), orgpolicy.ErrBundleExpired)

	assert.Error(t, orgpolicy.Verify(ctx, mxBundleFile(t, good), ""), "a missing key is refused")

	err := orgpolicy.Verify(ctx, filepath.Join(t.TempDir(), "absent.json"), k.pub)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read bundle")

	bad := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(bad, []byte("{"), 0o600))
	err = orgpolicy.Verify(ctx, bad, k.pub)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse bundle")
}

func TestInstall_InputAndFilesystemErrors(t *testing.T) {
	ctx := context.Background()
	mxPolicyDir(t)
	k := newKey(t)

	err := orgpolicy.Install(ctx, filepath.Join(t.TempDir(), "absent.json"), k.pub)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read bundle")

	bad := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(bad, []byte("[]"), 0o600))
	assert.Error(t, orgpolicy.Install(ctx, bad, k.pub))

	assert.Error(t, orgpolicy.Install(ctx, mxBundleFile(t, mxSigned(t, k, 1, time.Hour)), ""), "a missing key is refused")
	assert.ErrorIs(t, orgpolicy.Install(ctx, mxBundleFile(t, newTestBundle(1, time.Hour)), k.pub), orgpolicy.ErrSignatureInvalid, "unsigned")
	assert.ErrorIs(t, orgpolicy.Install(ctx, mxBundleFile(t, mxSigned(t, k, 1, -time.Minute)), k.pub), orgpolicy.ErrBundleExpired)

	blocker := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	t.Setenv("KEYLATCH_ORG_POLICY_DIR", filepath.Join(blocker, "dir"))
	assert.Error(t, orgpolicy.Install(ctx, mxBundleFile(t, mxSigned(t, k, 1, time.Hour)), k.pub))

	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "active.json", "occupied"), 0o700))
	t.Setenv("KEYLATCH_ORG_POLICY_DIR", dir)
	err = orgpolicy.Install(ctx, mxBundleFile(t, mxSigned(t, k, 1, time.Hour)), k.pub)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rename")
	active, _ := orgpolicy.Active(ctx)
	assert.Nil(t, active, "a failed install never becomes active")
}

func TestInstall_PinsFirstKeyAndRequiresNewerVersion(t *testing.T) {
	ctx := context.Background()
	mxPolicyDir(t)
	k := newKey(t)
	require.NoError(t, orgpolicy.Install(ctx, mxBundleFile(t, mxSigned(t, k, 2, time.Hour)), k.pub))

	assert.ErrorIs(t, orgpolicy.Install(ctx, mxBundleFile(t, mxSigned(t, k, 2, time.Hour)), k.pub), orgpolicy.ErrBundleVersionLow)
	other := newKey(t)
	assert.ErrorIs(t, orgpolicy.Install(ctx, mxBundleFile(t, mxSigned(t, other, 3, time.Hour)), other.pub), orgpolicy.ErrKeyMismatch)
	require.NoError(t, orgpolicy.Install(ctx, mxBundleFile(t, mxSigned(t, k, 3, time.Hour)), k.pub))
}

func TestActive_LoadsFromDiskAndRejectsTampering(t *testing.T) {
	ctx := context.Background()
	dir := mxPolicyDir(t)
	k := newKey(t)
	b := mxSigned(t, k, 5, time.Hour)
	require.NoError(t, orgpolicy.Install(ctx, mxBundleFile(t, b), k.pub))

	orgpolicy.ResetForTest()
	got, err := orgpolicy.Active(ctx)
	require.NoError(t, err)
	require.NotNil(t, got, "the installed bundle is reloaded from disk")
	assert.Equal(t, int64(5), got.Version)

	cached, err := orgpolicy.Active(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(5), cached.Version, "served from the cache on the next call")

	// Tampering with the on-disk file without re-signing disables it.
	orgpolicy.ResetForTest()
	tampered := *b
	tampered.BaselineDeny = []string{}
	tampered.AllowedEnvelope.AllowedEnvs = []string{"*"}
	raw, err := json.Marshal(tampered)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "active.json"), raw, 0o600))
	got, err = orgpolicy.Active(ctx)
	assert.ErrorIs(t, err, orgpolicy.ErrActiveUntrusted)
	assert.Nil(t, got)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "active.json"), []byte("{"), 0o600))
	got, err = orgpolicy.Active(ctx)
	assert.ErrorIs(t, err, orgpolicy.ErrActiveUntrusted)
	assert.Nil(t, got)

	// Without the pinned key nothing on disk can be trusted.
	raw, err = json.Marshal(b)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "active.json"), raw, 0o600))
	keyFiles, err := filepath.Glob(filepath.Join(dir, "*"))
	require.NoError(t, err)
	for _, f := range keyFiles {
		if filepath.Base(f) != "active.json" {
			require.NoError(t, os.Remove(f))
		}
	}
	got, err = orgpolicy.Active(ctx)
	assert.ErrorIs(t, err, orgpolicy.ErrActiveUntrusted)
	assert.Nil(t, got)
}

func TestActive_ExpiredBundleIsIgnored(t *testing.T) {
	ctx := context.Background()
	dir := mxPolicyDir(t)
	k := newKey(t)
	require.NoError(t, orgpolicy.Install(ctx, mxBundleFile(t, mxSigned(t, k, 1, time.Hour)), k.pub))

	orgpolicy.ResetForTest()
	raw, err := json.Marshal(mxSigned(t, k, 6, -time.Minute))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "active.json"), raw, 0o600))
	got, err := orgpolicy.Active(ctx)
	assert.NoError(t, err)
	assert.Nil(t, got, "an expired bundle on disk is ignored")
}

func TestCompose_EnvelopeRules(t *testing.T) {
	ctx := context.Background()
	b := &orgpolicy.OrgBundle{
		BaselineDeny: []string{"*.dump"},
		AllowedEnvelope: orgpolicy.AllowedEnvelope{
			DenyCapabilities: []string{"export*"},
			AllowedEnvs:      []string{"dev-*", "staging"},
			RequireApproval:  []string{"deploy?"},
		},
	}
	allow := orgpolicy.Decision{Allow: true}

	d := orgpolicy.Compose(ctx, b, allow, "vault.dump", "staging")
	assert.False(t, d.Allow)
	assert.Contains(t, d.Reason, "baseline")

	d = orgpolicy.Compose(ctx, b, allow, "export.all", "staging")
	assert.False(t, d.Allow)
	assert.Contains(t, d.Reason, "DenyCapabilities")

	d = orgpolicy.Compose(ctx, b, allow, "inject", "production")
	assert.False(t, d.Allow)
	assert.Contains(t, d.Reason, "not in org AllowedEnvelope.AllowedEnvs")

	d = orgpolicy.Compose(ctx, b, allow, "inject", "dev-alice")
	assert.True(t, d.Allow)
	assert.False(t, d.ApprovalRequired)

	d = orgpolicy.Compose(ctx, b, allow, "deploy1", "")
	assert.True(t, d.Allow, "an empty env skips the env check")
	assert.True(t, d.ApprovalRequired)
	assert.Contains(t, d.Reason, "approval required by org policy")

	already := orgpolicy.Decision{Allow: true, ApprovalRequired: true, Reason: "local"}
	d = orgpolicy.Compose(ctx, b, already, "deploy1", "staging")
	assert.Equal(t, "local", d.Reason, "existing local approval reason is preserved")

	star := &orgpolicy.OrgBundle{BaselineDeny: []string{"*"}}
	assert.False(t, orgpolicy.Compose(ctx, star, allow, "anything", "").Allow)
	bracket := &orgpolicy.OrgBundle{BaselineDeny: []string{"[", "read"}}
	assert.True(t, orgpolicy.Compose(ctx, bracket, allow, "write", "").Allow, "malformed globs never match unrelated values")
	assert.False(t, orgpolicy.Compose(ctx, bracket, allow, "read", "").Allow)
}

func TestBundleDir_DefaultsUnderHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("KEYLATCH_ORG_POLICY_DIR", "")
	orgpolicy.ResetForTest()
	t.Cleanup(orgpolicy.ResetForTest)

	k := newKey(t)
	require.NoError(t, orgpolicy.Install(context.Background(), mxBundleFile(t, mxSigned(t, k, 1, time.Hour)), k.pub))
	_, err := os.Stat(filepath.Join(home, ".keylatch", "team", "org-policy", "active.json"))
	assert.NoError(t, err)
}
