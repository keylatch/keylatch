package bw_test

// collections_test.go — organization collections, namespace mapping, the
// folder filter and the server check, all against a mocked bw CLI.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/bw"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testOrg     = "org-1"
	collections = `[{"id":"c-work","name":"Work/infra"},{"id":"c-ops","name":"Ops"},{"id":"c-misc","name":"Misc"}]`
	ciInWork    = `[{"id":"i-1","name":"ci","type":1,"organizationId":"org-1","collectionIds":["c-work"],"fields":[{"name":"api_key","value":"work-secret","type":1}]},` +
		`{"id":"i-9","name":"ci-extra","type":1,"organizationId":"org-1","collectionIds":["c-work"],"fields":[{"name":"api_key","value":"other","type":1}]}]`
)

func orgBackend(t *testing.T, responses map[string]kexec.MockResponse) (*bw.BitwardenBackend, *kexec.MockRunner) {
	t.Helper()
	runner := &kexec.MockRunner{Responses: responses}
	b, err := bw.Open(bw.Options{
		Bin:            fakeBWBin,
		Runner:         runner,
		Env:            func(string) string { return "" },
		OrganizationID: testOrg,
		Namespaces:     map[string]string{"work": "Work/infra", "ops": "Ops"},
	})
	require.NoError(t, err)
	return b, runner
}

func listCollections() string {
	return argKey(fakeBWBin, "list", "collections", "--organizationid="+testOrg)
}

func TestCollectionIDByName(t *testing.T) {
	b, runner := orgBackend(t, map[string]kexec.MockResponse{
		listCollections(): ok(collections),
		argKey(fakeBWBin, "list", "items", "--organizationid="+testOrg, "--collectionid=c-work", "--search=ci"): ok(ciInWork),
	})

	val, meta, err := b.Get(context.Background(), "work/ci/api_key")
	require.NoError(t, err)
	assert.Equal(t, "work-secret", string(val))
	assert.Equal(t, "i-1", string(meta.Accessor))

	_, _, err = b.Get(context.Background(), "work/ci/api_key")
	require.NoError(t, err)
	var lookups int
	for _, c := range runner.CallsCopy() {
		if len(c.Args) > 1 && c.Args[0] == "list" && c.Args[1] == "collections" {
			lookups++
		}
	}
	assert.Equal(t, 1, lookups, "the collection ID is resolved once")
}

func TestCollectionNameThatIsNotInTheOrganization(t *testing.T) {
	runner := &kexec.MockRunner{Responses: map[string]kexec.MockResponse{listCollections(): ok(collections)}}
	b, err := bw.Open(bw.Options{
		Bin: fakeBWBin, Runner: runner, Env: func(string) string { return "" },
		OrganizationID: testOrg, Namespaces: map[string]string{"work": "No/such"},
	})
	require.NoError(t, err)
	_, _, err = b.Get(context.Background(), "work/ci/api_key")
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

func TestOrganizationIDOnCreate(t *testing.T) {
	b, runner := orgBackend(t, map[string]kexec.MockResponse{
		listCollections(): ok(collections),
		argKey(fakeBWBin, "list", "items", "--organizationid="+testOrg, "--collectionid=c-work", "--search=deploy"): ok(`[]`),
		argKey(fakeBWBin, "create", "item"): ok(`{}`),
	})

	require.NoError(t, b.Set(context.Background(), "work/deploy/api_key", []byte("fresh-secret"), backend.Meta{}))

	var created []byte
	for _, c := range runner.CallsCopy() {
		if len(c.Args) == 2 && c.Args[0] == "create" {
			created = c.Stdin
			for _, a := range c.Args {
				assert.NotContains(t, a, "fresh-secret", "the value never reaches argv")
			}
		}
	}
	require.NotEmpty(t, created, "an item was created")
	body, err := base64.StdEncoding.DecodeString(string(created))
	require.NoError(t, err)
	var item struct {
		Name           string   `json:"name"`
		OrganizationID string   `json:"organizationId"`
		CollectionIDs  []string `json:"collectionIds"`
		FolderID       *string  `json:"folderId"`
	}
	require.NoError(t, json.Unmarshal(body, &item))
	assert.Equal(t, "deploy", item.Name)
	assert.Equal(t, testOrg, item.OrganizationID)
	assert.Equal(t, []string{"c-work"}, item.CollectionIDs)
	assert.Nil(t, item.FolderID)
}

func TestNamespaceMapping(t *testing.T) {
	opsItem := `[{"id":"i-2","name":"ci","type":1,"organizationId":"org-1","collectionIds":["c-ops"],"fields":[{"name":"api_key","value":"ops-secret","type":1}]}]`
	b, _ := orgBackend(t, map[string]kexec.MockResponse{
		listCollections(): ok(collections),
		argKey(fakeBWBin, "list", "items", "--organizationid="+testOrg, "--collectionid=c-work", "--search=ci"): ok(ciInWork),
		argKey(fakeBWBin, "list", "items", "--organizationid="+testOrg, "--collectionid=c-ops", "--search=ci"):  ok(opsItem),
		argKey(fakeBWBin, "list", "items", "--organizationid="+testOrg, "--collectionid=c-work"):                ok(ciInWork),
		argKey(fakeBWBin, "list", "items", "--organizationid="+testOrg, "--collectionid=c-ops"):                 ok(opsItem),
	})
	ctx := context.Background()

	work, _, err := b.Get(ctx, "work/ci/api_key")
	require.NoError(t, err)
	ops, _, err := b.Get(ctx, "ops/ci/api_key")
	require.NoError(t, err)
	assert.Equal(t, "work-secret", string(work))
	assert.Equal(t, "ops-secret", string(ops), "the same item name in another namespace is another item")

	entries, err := b.List(ctx, "")
	require.NoError(t, err)
	var paths []string
	for _, e := range entries {
		paths = append(paths, e.Path)
	}
	assert.Equal(t, []string{"ops/ci/api_key", "work/ci/api_key", "work/ci-extra/api_key"}, paths, "paths carry the namespace, namespaces in order")

	entries, err = b.List(ctx, "work/")
	require.NoError(t, err)
	assert.Len(t, entries, 2)
}

func TestMappedItemOutsideItsCollectionIsNotFound(t *testing.T) {
	stray := `[{"id":"i-7","name":"ci","type":1,"organizationId":"org-1","collectionIds":["c-misc"],"fields":[{"name":"api_key","value":"stray","type":1}]}]`
	b, _ := orgBackend(t, map[string]kexec.MockResponse{
		listCollections(): ok(collections),
		argKey(fakeBWBin, "list", "items", "--organizationid="+testOrg, "--collectionid=c-work", "--search=ci"): ok(stray),
	})
	_, _, err := b.Get(context.Background(), "work/ci/api_key")
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

func TestMappedLookupRefusesAmbiguousItems(t *testing.T) {
	twice := `[{"id":"i-1","name":"ci","organizationId":"org-1","collectionIds":["c-work"]},{"id":"i-2","name":"ci","organizationId":"org-1","collectionIds":["c-work"]}]`
	b, _ := orgBackend(t, map[string]kexec.MockResponse{
		listCollections(): ok(collections),
		argKey(fakeBWBin, "list", "items", "--organizationid="+testOrg, "--collectionid=c-work", "--search=ci"): ok(twice),
	})
	_, _, err := b.Get(context.Background(), "work/ci/api_key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "2 items named")
}

func TestMappedDelete(t *testing.T) {
	b, runner := orgBackend(t, map[string]kexec.MockResponse{
		listCollections(): ok(collections),
		argKey(fakeBWBin, "list", "items", "--organizationid="+testOrg, "--collectionid=c-work", "--search=ci"): ok(ciInWork),
		argKey(fakeBWBin, "delete", "item", "i-1"):                                                              ok(``),
	})
	require.NoError(t, b.Delete(context.Background(), "work/ci/api_key"))
	var deleted bool
	for _, c := range runner.CallsCopy() {
		deleted = deleted || (len(c.Args) == 3 && c.Args[0] == "delete" && c.Args[2] == "i-1")
	}
	assert.True(t, deleted)

	_, _ = orgBackend(t, nil)
	err := b.Delete(context.Background(), "nowhere/ci/api_key")
	assert.ErrorIs(t, err, bw.ErrNamespaceUnmapped)
}

func TestUnmappedNamespaceFailsClosed(t *testing.T) {
	b, runner := orgBackend(t, map[string]kexec.MockResponse{listCollections(): ok(collections)})
	ctx := context.Background()

	_, _, err := b.Get(ctx, "personal/ci/api_key")
	assert.ErrorIs(t, err, bw.ErrNamespaceUnmapped)
	assert.ErrorContains(t, err, `"personal"`)
	assert.ErrorIs(t, b.Set(ctx, "personal/ci/api_key", []byte("v"), backend.Meta{}), bw.ErrNamespaceUnmapped)
	assert.ErrorIs(t, b.Delete(ctx, "personal/ci/api_key"), bw.ErrNamespaceUnmapped)
	_, _, err = b.Get(ctx, "ci/api_key")
	assert.ErrorIs(t, err, bw.ErrNamespaceUnmapped, "a path without a namespace is in the default namespace, which is not mapped here")

	assert.Empty(t, runner.CallsCopy(), "no bw call is made for an unmapped namespace")
	assert.True(t, errors.Is(err, bw.ErrNamespaceUnmapped))
}

func TestOrganizationWithoutNamespacesMapsNothing(t *testing.T) {
	runner := &kexec.MockRunner{}
	b, err := bw.Open(bw.Options{Bin: fakeBWBin, Runner: runner, Env: func(string) string { return "" }, OrganizationID: testOrg})
	require.NoError(t, err)
	_, _, err = b.Get(context.Background(), "default/ci/api_key")
	assert.ErrorIs(t, err, bw.ErrNamespaceUnmapped)
	assert.Empty(t, runner.CallsCopy())
}

func TestNamespaceOptionValidation(t *testing.T) {
	base := bw.Options{Bin: fakeBWBin, Runner: &kexec.MockRunner{}, Env: func(string) string { return "" }}

	noOrg := base
	noOrg.Namespaces = map[string]string{"work": "Work"}
	_, err := bw.Open(noOrg)
	assert.ErrorContains(t, err, "organization_id")

	withFolder := base
	withFolder.OrganizationID, withFolder.Namespaces, withFolder.Folder = testOrg, map[string]string{"work": "Work"}, "keylatch"
	_, err = bw.Open(withFolder)
	assert.ErrorContains(t, err, "replace folder and collection")
}

func TestServerMismatchRefused(t *testing.T) {
	const server = "https://vault.example.com"
	open := func(configured string) (*bw.BitwardenBackend, *kexec.MockRunner) {
		runner := &kexec.MockRunner{Responses: map[string]kexec.MockResponse{
			argKey(fakeBWBin, "config", "server"):          ok(configured + "\n"),
			argKey(fakeBWBin, "get", "item", "openrouter"): {Stdout: testdataBytes(t, "item_get_openrouter.json")},
		}}
		b, err := bw.Open(bw.Options{Bin: fakeBWBin, Runner: runner, Env: func(string) string { return "" }, Server: server})
		require.NoError(t, err)
		return b, runner
	}

	b, runner := open("https://bitwarden.com")
	_, _, err := b.Get(context.Background(), "default/openrouter/api_key")
	require.ErrorIs(t, err, bw.ErrServerMismatch)
	assert.ErrorContains(t, err, "bw config server "+server)
	for _, c := range runner.CallsCopy() {
		assert.NotEqual(t, "get", c.Args[0], "no item is read from the wrong server")
	}
	assert.ErrorIs(t, b.Set(context.Background(), "default/openrouter/api_key", []byte("v"), backend.Meta{}), bw.ErrServerMismatch)
	assert.ErrorIs(t, b.Delete(context.Background(), "default/openrouter/api_key"), bw.ErrServerMismatch)
	_, err = b.List(context.Background(), "")
	assert.ErrorIs(t, err, bw.ErrServerMismatch)

	b, runner = open(server + "/")
	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.NoError(t, err, "a trailing slash and letter case do not matter")
	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.NoError(t, err)
	var checks int
	for _, c := range runner.CallsCopy() {
		if c.Args[0] == "config" {
			checks++
		}
	}
	assert.Equal(t, 1, checks, "a matching server is checked once")
}

func TestServerCheckErrors(t *testing.T) {
	for name, resp := range map[string]kexec.MockResponse{
		"runner error": {Err: errors.New("exec failed")},
		"bw failure":   {ExitCode: 1},
	} {
		runner := &kexec.MockRunner{Responses: map[string]kexec.MockResponse{argKey(fakeBWBin, "config", "server"): resp}}
		b, err := bw.Open(bw.Options{Bin: fakeBWBin, Runner: runner, Env: func(string) string { return "" }, Server: "https://vault.example.com"})
		require.NoError(t, err)
		_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
		assert.Error(t, err, name)
		assert.NotErrorIs(t, err, bw.ErrServerMismatch, name)
	}
}

func TestFolderFilterMatchesConfiguredFolderOnly(t *testing.T) {
	folders := `[{"id":"f-keylatch","name":"keylatch"},{"id":"f-other","name":"other"}]`
	list := `[` +
		`{"id":"i-1","name":"mine","folderId":"f-keylatch","fields":[{"name":"api_key","value":"","type":1}]},` +
		`{"id":"i-2","name":"theirs","folderId":"f-other","fields":[{"name":"api_key","value":"","type":1}]},` +
		`{"id":"i-3","name":"loose","folderId":null,"fields":[{"name":"api_key","value":"","type":1}]}]`
	runner := &kexec.MockRunner{Responses: map[string]kexec.MockResponse{
		argKey(fakeBWBin, "list", "folders"):                    ok(folders),
		argKey(fakeBWBin, "list", "items", "--search=keylatch"): ok(list),
		argKey(fakeBWBin, "get", "item", "theirs"):              ok(`{"id":"i-2","name":"theirs","folderId":"f-other","fields":[{"name":"api_key","value":"v","type":1}]}`),
		argKey(fakeBWBin, "get", "item", "mine"):                ok(`{"id":"i-1","name":"mine","folderId":"f-keylatch","fields":[{"name":"api_key","value":"v","type":1}]}`),
	}}
	b, err := bw.Open(bw.Options{Bin: fakeBWBin, Runner: runner, Env: func(string) string { return "" }, Folder: "keylatch"})
	require.NoError(t, err)
	ctx := context.Background()

	entries, err := b.List(ctx, "")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "default/mine/api_key", entries[0].Path, "an item in another folder, or in none, is not listed")

	_, _, err = b.Get(ctx, "default/theirs/api_key")
	assert.ErrorIs(t, err, backend.ErrNotFound, "an item in another folder is not readable")
	val, _, err := b.Get(ctx, "default/mine/api_key")
	require.NoError(t, err)
	assert.Equal(t, "v", string(val))
}

func TestMissingFolderListsNothing(t *testing.T) {
	runner := &kexec.MockRunner{Responses: map[string]kexec.MockResponse{
		argKey(fakeBWBin, "list", "folders"):                    ok(`[]`),
		argKey(fakeBWBin, "list", "items", "--search=keylatch"): ok(`[{"id":"i-1","name":"x","folderId":"f-1","fields":[{"name":"k","value":"","type":1}]}]`),
	}}
	b, err := bw.Open(bw.Options{Bin: fakeBWBin, Runner: runner, Env: func(string) string { return "" }, Folder: "missing"})
	require.NoError(t, err)
	entries, err := b.List(context.Background(), "")
	require.NoError(t, err)
	assert.Empty(t, entries)
}
