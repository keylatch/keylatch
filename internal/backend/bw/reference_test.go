package bw_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/bw"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/store"
)

const (
	refSession = "KEYLATCH_CANARY_BW_SESSION_0xC0FFEE"
	refValue   = "KEYLATCH_CANARY_REF_VALUE_0xBEEF"
	orgID      = "11111111-1111-1111-1111-111111111111"
	itemA      = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	itemB      = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	collID     = "cccccccc-cccc-cccc-cccc-cccccccccccc"
)

func refRunner(resp map[string]kexec.MockResponse) *kexec.MockRunner {
	return &kexec.MockRunner{Responses: resp}
}

func ok(json string) kexec.MockResponse { return kexec.MockResponse{Stdout: []byte(json)} }

func openRef(t *testing.T, r *kexec.MockRunner) *bw.BitwardenBackend {
	t.Helper()
	b, err := bw.Open(bw.Options{Bin: fakeBWBin, Runner: r, Env: func(k string) string {
		if k == "BW_SESSION" {
			return refSession
		}
		return ""
	}})
	require.NoError(t, err)
	return b
}

func mustRef(t *testing.T, rest string) store.BWRef {
	t.Helper()
	ref, err := store.ParseBWRef(rest)
	require.NoError(t, err)
	return ref
}

func assertSessionOnlyInEnv(t *testing.T, r *kexec.MockRunner) {
	t.Helper()
	for _, c := range r.CallsCopy() {
		assert.NotContains(t, strings.Join(c.Args, " "), refSession)
		assert.Contains(t, c.Env, "BW_SESSION="+refSession)
	}
}

func TestResolveRef_PersonalVault_NameWithSpaces(t *testing.T) {
	t.Parallel()
	r := refRunner(map[string]kexec.MockResponse{
		argKey(fakeBWBin, "list", "items", "--search=My Service"): ok(`[
			{"id":"` + itemA + `","name":"My Service","login":{"username":"u","password":"` + refValue + `"}},
			{"id":"` + itemB + `","name":"My Service Old","login":{"password":"other"}},
			{"id":"dddddddd-dddd-dddd-dddd-dddddddddddd","name":"My Service","organizationId":"` + orgID + `","login":{"password":"org"}}]`),
	})
	got, err := openRef(t, r).ResolveRef(context.Background(), mustRef(t, "personal/-/My%20Service/password"))
	require.NoError(t, err)
	assert.Equal(t, refValue, string(got))
	assertSessionOnlyInEnv(t, r)
}

func TestResolveRef_PersonalFolder(t *testing.T) {
	t.Parallel()
	r := refRunner(map[string]kexec.MockResponse{
		argKey(fakeBWBin, "list", "folders"):                                ok(`[{"id":"f1","name":"Work/APIs"}]`),
		argKey(fakeBWBin, "list", "items", "--search=svc", "--folderid=f1"): ok(`[{"id":"` + itemA + `","name":"svc","login":{"username":"` + refValue + `"}}]`),
	})
	got, err := openRef(t, r).ResolveRef(context.Background(), mustRef(t, "personal/Work%2FAPIs/svc/username"))
	require.NoError(t, err)
	assert.Equal(t, refValue, string(got))
}

func TestResolveRef_OrgCollection_CustomField(t *testing.T) {
	t.Parallel()
	r := refRunner(map[string]kexec.MockResponse{
		argKey(fakeBWBin, "list", "organizations"):                          ok(`[{"id":"` + orgID + `","name":"Acme / EU"}]`),
		argKey(fakeBWBin, "list", "collections", "--organizationid="+orgID): ok(`[{"id":"` + collID + `","name":"Team Keys/Prod"}]`),
		argKey(fakeBWBin, "list", "items", "--search=Stripe", "--organizationid="+orgID, "--collectionid="+collID): ok(
			`[{"id":"` + itemA + `","name":"Stripe","organizationId":"` + orgID + `","collectionIds":["` + collID + `"],
			"fields":[{"name":"api key","value":"` + refValue + `","type":1}]}]`),
	})
	got, err := openRef(t, r).ResolveRef(context.Background(), mustRef(t, "Acme%20%2F%20EU/Team%20Keys%2FProd/Stripe/api%20key"))
	require.NoError(t, err)
	assert.Equal(t, refValue, string(got))
	assertSessionOnlyInEnv(t, r)
}

func TestResolveRef_Notes(t *testing.T) {
	t.Parallel()
	r := refRunner(map[string]kexec.MockResponse{
		argKey(fakeBWBin, "get", "item", itemA): ok(`{"id":"` + itemA + `","name":"n","notes":"` + refValue + `"}`),
	})
	got, err := openRef(t, r).ResolveRef(context.Background(), mustRef(t, "personal/-/"+itemA+"/notes"))
	require.NoError(t, err)
	assert.Equal(t, refValue, string(got))
}

func TestResolveRef_DuplicateNames_Rejected(t *testing.T) {
	t.Parallel()
	r := refRunner(map[string]kexec.MockResponse{
		argKey(fakeBWBin, "list", "items", "--search=dup"): ok(`[
			{"id":"` + itemA + `","name":"dup","login":{"password":"` + refValue + `"}},
			{"id":"` + itemB + `","name":"dup","login":{"password":"` + refValue + `"}}]`),
	})
	ref := mustRef(t, "personal/-/dup/password")
	_, err := openRef(t, r).ResolveRef(context.Background(), ref)
	require.Error(t, err)
	assert.Contains(t, err.Error(), itemA)
	assert.Contains(t, err.Error(), itemB)
	assert.NotContains(t, err.Error(), refValue)

	_, err = bw.CanonicalizeRef(context.Background(), r, fakeBWBin, ref)
	require.Error(t, err)
}

func TestResolveRef_MissingField(t *testing.T) {
	t.Parallel()
	r := refRunner(map[string]kexec.MockResponse{
		argKey(fakeBWBin, "get", "item", itemA): ok(`{"id":"` + itemA + `","name":"n","fields":[{"name":"other","value":"x"}],"login":{"password":"p"}}`),
	})
	b := openRef(t, r)
	for _, rest := range []string{"personal/-/" + itemA + "/missing", "personal/-/" + itemA + "/username", "personal/-/" + itemA + "/notes"} {
		_, err := b.ResolveRef(context.Background(), mustRef(t, rest))
		require.Error(t, err, rest)
		assert.True(t, errors.Is(err, backend.ErrNotFound), rest)
	}
}

func TestResolveRef_ItemNotFound(t *testing.T) {
	t.Parallel()
	r := refRunner(map[string]kexec.MockResponse{
		argKey(fakeBWBin, "list", "items", "--search=ghost"): ok(`[]`),
	})
	_, err := openRef(t, r).ResolveRef(context.Background(), mustRef(t, "personal/-/ghost/password"))
	assert.True(t, errors.Is(err, backend.ErrNotFound))
}

func TestResolveRef_IDInWrongScope(t *testing.T) {
	t.Parallel()
	r := refRunner(map[string]kexec.MockResponse{
		argKey(fakeBWBin, "get", "item", itemA): ok(`{"id":"` + itemA + `","organizationId":"` + orgID + `","login":{"password":"p"}}`),
	})
	_, err := openRef(t, r).ResolveRef(context.Background(), mustRef(t, "personal/-/"+itemA+"/password"))
	assert.True(t, errors.Is(err, backend.ErrNotFound))
}

func TestResolveRef_LockedVault(t *testing.T) {
	t.Parallel()
	for name, resp := range map[string]kexec.MockResponse{
		"stderr":       {Stderr: []byte("Vault is locked."), ExitCode: 1},
		"empty stdout": {},
	} {
		resp := resp
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := refRunner(map[string]kexec.MockResponse{argKey(fakeBWBin, "list", "items", "--search=x"): resp})
			_, err := openRef(t, r).ResolveRef(context.Background(), mustRef(t, "personal/-/x/password"))
			assert.True(t, errors.Is(err, backend.ErrLocked))
		})
	}
}

func TestCanonicalizeRef_ResolvesToIDs(t *testing.T) {
	t.Parallel()
	r := refRunner(map[string]kexec.MockResponse{
		argKey(fakeBWBin, "list", "organizations"): ok(`[{"id":"` + orgID + `","name":"Acme"}]`),
		argKey(fakeBWBin, "list", "items", "--search=Stripe", "--organizationid="+orgID): ok(
			`[{"id":"` + itemA + `","name":"Stripe","organizationId":"` + orgID + `","login":{"password":"` + refValue + `"}}]`),
	})
	got, err := bw.CanonicalizeRef(context.Background(), r, fakeBWBin, mustRef(t, "Acme/-/Stripe/password"))
	require.NoError(t, err)
	assert.Equal(t, "bw://"+orgID+"/-/"+itemA+"/password", got.String())
	assert.NotContains(t, got.String(), refValue)
}

func TestResolverDispatch_BW(t *testing.T) {
	t.Parallel()
	r := refRunner(map[string]kexec.MockResponse{
		argKey(fakeBWBin, "get", "item", itemA): ok(`{"id":"` + itemA + `","login":{"password":"` + refValue + `"}}`),
	})
	res := store.NewResolver(r).WithBinOverride("bw", fakeBWBin)
	got, err := res.Resolve(context.Background(), "bw://personal/-/"+itemA+"/password")
	require.NoError(t, err)
	assert.Equal(t, refValue, string(got))
}
