package sharedsecret_test

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/team/sharedsecret"
	"github.com/keylatch/keylatch/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreate_SkipsMembersWithoutKeysAndRejectsBadKeys(t *testing.T) {
	ctx := context.Background()
	m, _ := newTestMember(t, "alice")
	nokey := team.Member{ID: "bob", HMAC: "hmac-bob"}

	s, err := sharedsecret.Create(ctx, "team-1", "db-password", []byte("v"), []team.Member{m, nokey})
	require.NoError(t, err)
	require.Len(t, s.Recipients, 1)
	assert.Equal(t, "hmac-alice", s.Recipients[0].MemberIDHMAC)
	assert.Equal(t, 1, s.Version)
	assert.NotContains(t, s.NameHMAC, "db-password")
	other, err := sharedsecret.Create(ctx, "team-2", "db-password", []byte("v"), nil)
	require.NoError(t, err)
	assert.NotEqual(t, s.NameHMAC, other.NameHMAC, "name digests are scoped per team")

	for name, key := range map[string]string{"not hex": "zz", "wrong length": "abcd"} {
		bad := team.Member{ID: "eve", HMAC: "hmac-eve", AgePublicKey: key}
		_, err := sharedsecret.Create(ctx, "team-1", "x", []byte("v"), []team.Member{bad})
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), "decode recipient public key", name)

		_, err = sharedsecret.RotateWithPlaintext(ctx, s, []byte("v"), []team.Member{bad})
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), "rotate for member", name)
	}
}

func TestRead_RecipientAndKeyErrors(t *testing.T) {
	ctx := context.Background()
	m, priv := newTestMember(t, "alice")
	s, err := sharedsecret.Create(ctx, "team-1", "n", []byte("secret-bytes"), []team.Member{m})
	require.NoError(t, err)

	_, err = sharedsecret.Read(ctx, s, team.Member{HMAC: "hmac-stranger", AgePublicKey: priv}, validProof())
	assert.ErrorIs(t, err, sharedsecret.ErrNoRecipientFound)

	_, err = sharedsecret.Read(ctx, s, team.Member{HMAC: "hmac-alice"}, validProof())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no AGE public key")

	_, err = sharedsecret.Read(ctx, s, team.Member{HMAC: "hmac-alice", AgePublicKey: "zz"}, validProof())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode private key")

	wrongPriv, _, err := sharedsecret.GenerateAGEKeyPair()
	require.NoError(t, err)
	_, err = sharedsecret.Read(ctx, s, team.Member{HMAC: "hmac-alice", AgePublicKey: wrongPriv}, validProof())
	assert.ErrorIs(t, err, sharedsecret.ErrDecryptionFailed, "a different private key cannot decrypt")

	short := *s
	short.Recipients = []sharedsecret.RecipientEntry{{MemberIDHMAC: "hmac-alice", EncryptedPayload: []byte("tiny")}}
	_, err = sharedsecret.Read(ctx, &short, team.Member{HMAC: "hmac-alice", AgePublicKey: priv}, validProof())
	assert.ErrorIs(t, err, sharedsecret.ErrDecryptionFailed)
}

func TestRewrap_RefusesWithoutPlaintext(t *testing.T) {
	ctx := context.Background()
	m, _ := newTestMember(t, "carol")
	s := &sharedsecret.SharedSecret{ID: "s"}

	_, err := sharedsecret.Rewrap(ctx, s, trust.PresenceProof{}, m)
	assert.ErrorIs(t, err, sharedsecret.ErrHardwarePresenceRequired)

	_, err = sharedsecret.Rewrap(ctx, s, validProof(), team.Member{ID: "nokey"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no AGE public key")

	_, err = sharedsecret.Rewrap(ctx, s, validProof(), m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RotateWithPlaintext")
}
