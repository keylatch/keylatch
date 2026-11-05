package mintsession_test

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/mintsession"
	"github.com/keylatch/keylatch/internal/mintsession/mintsessiontest"
	"github.com/keylatch/keylatch/internal/policy/mint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mintedReq(caller mint.CallerKind) mintsession.Request {
	r := req(mintsessiontest.Owner+"/app", "contents=write")
	r.Caller, r.RuntimeMode = caller, "minted"
	return r
}

func TestMintedRuntimeAppliesTheMintCallerPolicy(t *testing.T) {
	p := policy()
	p.Callers = []string{"human"}
	f := setup(t, p)

	_, err := f.m.Open(context.Background(), mintedReq(mint.CallerAgent))
	require.ErrorIs(t, err, mint.ErrDenied, "an agent can never hold a minted token, even when placeholder_callers lists it")

	_, err = f.m.Open(context.Background(), mintedReq(mint.CallerHost))
	require.ErrorIs(t, err, mint.ErrDenied, "a caller kind the policy does not list is refused")

	cred, err := f.m.Open(context.Background(), mintedReq(mint.CallerHuman))
	require.NoError(t, err)
	_, err = cred.Value(context.Background(), mintsession.TokenField)
	require.NoError(t, err)

	events := f.audit.Events()
	require.Len(t, events, 1)
	assert.Equal(t, audit.ActionMint, events[0].Action)
	assert.Equal(t, "minted", events[0].RuntimeMode)

	cred.Close()
	assert.Equal(t, []string{mintsessiontest.Token(1)}, f.stub.Revoked(), "the token is revoked when the run ends")
}

func TestPlaceholderRuntimeKeepsTheAgentPolicy(t *testing.T) {
	f := setup(t, policy())
	cred, err := f.m.Open(context.Background(), req(mintsessiontest.Owner+"/app", "contents=write"))
	require.NoError(t, err)
	_, err = cred.Value(context.Background(), mintsession.TokenField)
	require.NoError(t, err)
	assert.Equal(t, "placeholder", f.audit.Events()[0].RuntimeMode)
	cred.Close()
}
