package cli

import (
	"context"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/vault"
)

func TestUserSource_SecretsReadsEveryStoredValue(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	ctx := context.Background()
	store := newDispatchedStore(f.cfg, f.env)
	want := map[string]string{
		"default/ai/openai/apikey":    caSecret("openai"),
		"default/ai/anthropic/apikey": caSecret("anthropic"),
	}
	for p, v := range want {
		require.NoError(t, store.Set(ctx, p, []byte(v), backend.Meta{}))
	}

	src := &userSource{cfg: f.cfg, env: f.env}
	items, err := src.Secrets(ctx)
	require.NoError(t, err)
	got := map[string]string{}
	for _, it := range items {
		got[it.Path] = string(it.Value)
	}
	assert.Equal(t, want, got)
}

func TestUserSource_NothingToMoveWithoutLogOrTokens(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	src := newUserSource(&cobra.Command{}, f.env)

	head, err := src.AuditHead()
	require.NoError(t, err)
	assert.Empty(t, head, "no audit log means no chain head to carry over")

	n, err := src.RevokeTokens(context.Background())
	require.NoError(t, err)
	assert.Zero(t, n, "no token store means nothing to revoke")
}

func TestUserSink_PutStoresTheNextVersion(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	ctx := context.Background()
	sink, done, err := newUserSink(&cobra.Command{}, f.env)
	require.NoError(t, err)
	t.Cleanup(done)
	sink.cfg = f.cfg
	require.NoError(t, sink.Prepare(ctx))

	const path = "default/ai/openai/apikey"
	require.NoError(t, sink.Put(ctx, path, []byte(caSecret("first"))))
	require.NoError(t, sink.Put(ctx, path, []byte(caSecret("second"))))

	ctx = audit.WithEmitter(ctx, audit.AsEmitter(sink.logger))
	m, err := vault.GetMeta(ctx, path, f.cfg, f.env)
	require.NoError(t, err)
	assert.Equal(t, 2, m.CurrentVersion, "a second put is the next version, not an overwrite")
	v, _, err := vault.GetVersion(ctx, path, 2, f.cfg, f.env)
	require.NoError(t, err)
	assert.Equal(t, caSecret("second"), string(v))
}
