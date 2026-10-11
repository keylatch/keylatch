package bw_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/bw"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/vault/meta"
)

type bkBWWireField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  int    `json:"type"`
}

type bkBWWireItem struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Type          int             `json:"type"`
	FolderID      *string         `json:"folderId"`
	CollectionIDs []string        `json:"collectionIds"`
	Fields        []bkBWWireField `json:"fields"`
}

var bkBWNotFound = kexec.MockResponse{Stderr: []byte("Not found."), ExitCode: 1}

func bkBWOpen(t *testing.T, runner kexec.CommandRunner, opts bw.Options) *bw.BitwardenBackend {
	t.Helper()
	opts.Bin = fakeBWBin
	opts.Runner = runner
	if opts.Env == nil {
		opts.Env = func(string) string { return "" }
	}
	b, err := bw.Open(opts)
	require.NoError(t, err)
	return b
}

// bkBWDecodeCall decodes the base64 JSON payload piped to create/edit.
func bkBWDecodeCall(t *testing.T, c kexec.MockCall) bkBWWireItem {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(string(c.Stdin))
	require.NoError(t, err)
	var item bkBWWireItem
	require.NoError(t, json.Unmarshal(raw, &item))
	return item
}

func bkBWFindCall(t *testing.T, r *kexec.MockRunner, verb string) kexec.MockCall {
	t.Helper()
	for _, c := range r.Calls {
		if len(c.Args) > 0 && c.Args[0] == verb {
			return c
		}
	}
	t.Fatalf("no %q call recorded; calls=%v", verb, r.Calls)
	return kexec.MockCall{}
}

func TestBWStubs_NotSupported(t *testing.T) {
	ctx := context.Background()
	b := bkBWOpen(t, &kexec.MockRunner{}, bw.Options{Server: "https://vw.example.test"})

	assert.Equal(t, "bw", b.Name())
	assert.Equal(t, "bw:https://vw.example.test", b.ID())
	assert.ElementsMatch(t, []backend.Capability{backend.CapList, backend.CapMetadata, backend.CapImport, backend.CapExport}, b.Capabilities())
	assert.NoError(t, b.Close())

	_, err := b.GetMeta(ctx, "default/a/b")
	assert.ErrorIs(t, err, backend.ErrNotSupported)
	assert.ErrorIs(t, b.SetMeta(ctx, "default/a/b", meta.Meta{}), backend.ErrNotSupported)
	_, err = b.ListMeta(ctx, "")
	assert.ErrorIs(t, err, backend.ErrNotSupported)
	_, err = b.GetVersioned(ctx, "default/a/b", 1)
	assert.ErrorIs(t, err, backend.ErrNotSupported)
	assert.ErrorIs(t, b.SetVersioned(ctx, "default/a/b", 1, []byte("v")), backend.ErrNotSupported)
	assert.ErrorIs(t, b.DeleteVersioned(ctx, "default/a/b", 1), backend.ErrNotSupported)
}

func TestBWSet_CreatesItemWithFieldTypesFolderAndCollection(t *testing.T) {
	runner := &kexec.MockRunner{Responses: map[string]kexec.MockResponse{
		argKey(fakeBWBin, "get", "item", "svc"): bkBWNotFound,
		argKey(fakeBWBin, "list", "folders"):    {Stdout: []byte(`[{"id":"f-other","name":"Other"},{"id":"f-123","name":"Keylatch"}]`)},
	}}
	b := bkBWOpen(t, runner, bw.Options{Folder: "Keylatch", Collection: "col-9"})

	value := "s3cr" + "et-value"
	require.NoError(t, b.Set(context.Background(), "default/svc/api_token", []byte(value), backend.Meta{}))

	call := bkBWFindCall(t, runner, "create")
	require.Len(t, call.Args, 2)
	assert.Equal(t, "item", call.Args[1])
	item := bkBWDecodeCall(t, call)
	assert.Equal(t, "svc", item.Name)
	assert.Equal(t, 1, item.Type)
	require.NotNil(t, item.FolderID)
	assert.Equal(t, "f-123", *item.FolderID)
	assert.Equal(t, []string{"col-9"}, item.CollectionIDs)
	require.Len(t, item.Fields, 1)
	assert.Equal(t, bkBWWireField{Name: "api_token", Value: value, Type: 1}, item.Fields[0])

	for _, c := range runner.Calls {
		for _, a := range c.Args {
			assert.NotContains(t, a, "--session")
		}
	}

	require.NoError(t, b.Set(context.Background(), "default/svc/base_url", []byte("https://x.test"), backend.Meta{}))
	var plain bkBWWireItem
	for _, c := range runner.Calls {
		if c.Args[0] == "create" {
			plain = bkBWDecodeCall(t, c)
		}
	}
	require.Len(t, plain.Fields, 1)
	assert.Equal(t, 0, plain.Fields[0].Type, "non-secret field names are stored as plain text")
}

func TestBWSet_FolderResolutionFailureOmitsFolder(t *testing.T) {
	cases := map[string]kexec.MockResponse{
		"list fails":     {ExitCode: 1},
		"runner error":   {Err: errors.New("boom")},
		"bad json":       {Stdout: []byte("not json")},
		"folder missing": {Stdout: []byte(`[{"id":"f-1","name":"Elsewhere"}]`)},
	}
	for name, resp := range cases {
		t.Run(name, func(t *testing.T) {
			runner := &kexec.MockRunner{Responses: map[string]kexec.MockResponse{
				argKey(fakeBWBin, "get", "item", "svc"): bkBWNotFound,
				argKey(fakeBWBin, "list", "folders"):    resp,
			}}
			b := bkBWOpen(t, runner, bw.Options{Folder: "Keylatch"})
			require.NoError(t, b.Set(context.Background(), "default/svc/api_key", []byte("v"), backend.Meta{}))
			item := bkBWDecodeCall(t, bkBWFindCall(t, runner, "create"))
			assert.Nil(t, item.FolderID)
			assert.Empty(t, item.CollectionIDs)
		})
	}
}

func TestBWSet_UpdatesExistingField(t *testing.T) {
	existing := `{"id":"it-1","name":"svc","type":1,"fields":[{"name":"api_key","value":"old","type":0},{"name":"note","value":"n","type":0}]}`
	runner := &kexec.MockRunner{Responses: map[string]kexec.MockResponse{
		argKey(fakeBWBin, "get", "item", "svc"): {Stdout: []byte(existing)},
	}}
	b := bkBWOpen(t, runner, bw.Options{})

	require.NoError(t, b.Set(context.Background(), "default/svc/api_key", []byte("new"), backend.Meta{}))
	call := bkBWFindCall(t, runner, "edit")
	require.Len(t, call.Args, 3)
	assert.Equal(t, []string{"edit", "item", "it-1"}, call.Args[:3])
	item := bkBWDecodeCall(t, call)
	assert.Equal(t, []bkBWWireField{
		{Name: "api_key", Value: "new", Type: 1},
		{Name: "note", Value: "n", Type: 0},
	}, item.Fields)
}

func TestBWSet_AppendsNewFieldToExistingItem(t *testing.T) {
	existing := `{"id":"it-1","name":"svc","type":1,"fields":[{"name":"note","value":"n","type":0}]}`
	runner := &kexec.MockRunner{Responses: map[string]kexec.MockResponse{
		argKey(fakeBWBin, "get", "item", "svc"): {Stdout: []byte(existing)},
	}}
	b := bkBWOpen(t, runner, bw.Options{})

	require.NoError(t, b.Set(context.Background(), "svc/client_secret", []byte("val"), backend.Meta{}))
	item := bkBWDecodeCall(t, bkBWFindCall(t, runner, "edit"))
	require.Len(t, item.Fields, 2)
	assert.Equal(t, bkBWWireField{Name: "client_secret", Value: "val", Type: 1}, item.Fields[1])
}

// bkBWVerbRunner answers by the first argument (the bw sub-command) so tests
// need not reproduce the exact base64 payload.
type bkBWVerbRunner struct {
	mu    sync.Mutex
	resp  map[string]kexec.MockResponse
	calls [][]string
}

func (r *bkBWVerbRunner) Run(_ context.Context, _ string, args []string, _ []byte) ([]byte, []byte, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, append([]string(nil), args...))
	res := r.resp[args[0]]
	return res.Stdout, res.Stderr, res.ExitCode, res.Err
}

func TestBWSet_ErrorMapping(t *testing.T) {
	existing := kexec.MockResponse{Stdout: []byte(`{"id":"it-1","name":"svc","fields":[]}`)}
	cases := []struct {
		name    string
		get     kexec.MockResponse
		verb    string
		write   kexec.MockResponse
		wantIs  error
		wantSub string
	}{
		{"create runner error", bkBWNotFound, "create", kexec.MockResponse{Err: errors.New("spawn failed")}, nil, "runner error"},
		{"create locked", bkBWNotFound, "create", kexec.MockResponse{Stderr: []byte("Vault is locked."), ExitCode: 1}, backend.ErrLocked, "BW_SESSION"},
		{"create other exit", bkBWNotFound, "create", kexec.MockResponse{Stderr: []byte("weird failure detail"), ExitCode: 2}, nil, "bw exited 2"},
		{"edit runner error", existing, "edit", kexec.MockResponse{Err: errors.New("spawn failed")}, nil, "runner error"},
		{"edit locked", existing, "edit", kexec.MockResponse{Stderr: []byte("You are not logged in."), ExitCode: 1}, backend.ErrLocked, "BW_SESSION"},
		{"edit other exit", existing, "edit", kexec.MockResponse{Stderr: []byte("weird failure detail"), ExitCode: 3}, nil, "bw exited 3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &bkBWVerbRunner{resp: map[string]kexec.MockResponse{"get": tc.get, tc.verb: tc.write}}
			b := bkBWOpen(t, runner, bw.Options{})
			err := b.Set(context.Background(), "default/svc/api_key", []byte("v"), backend.Meta{})
			require.Error(t, err)
			if tc.wantIs != nil {
				assert.ErrorIs(t, err, tc.wantIs)
			}
			assert.Contains(t, err.Error(), tc.wantSub)
			assert.NotContains(t, err.Error(), "weird failure detail", "raw stderr must not be echoed")
			assert.Equal(t, tc.verb, runner.calls[len(runner.calls)-1][0])
		})
	}
}

func TestBWSet_InvalidPath(t *testing.T) {
	b := bkBWOpen(t, &kexec.MockRunner{}, bw.Options{})
	err := b.Set(context.Background(), "nofield", []byte("v"), backend.Meta{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid canonical path")
}

func TestBWDelete_Paths(t *testing.T) {
	item := kexec.MockResponse{Stdout: []byte(`{"id":"it-7","name":"svc"}`)}
	cases := []struct {
		name    string
		get     kexec.MockResponse
		del     kexec.MockResponse
		wantIs  error
		wantSub string
		wantDel bool
	}{
		{name: "success", get: item, wantDel: true},
		{name: "item missing", get: bkBWNotFound, wantIs: backend.ErrNotFound, wantSub: "svc"},
		{name: "get generic failure", get: kexec.MockResponse{Stderr: []byte("kaboom detail"), ExitCode: 4}, wantSub: "get item exited 4"},
		{name: "delete runner error", get: item, del: kexec.MockResponse{Err: errors.New("spawn")}, wantSub: "runner error", wantDel: true},
		{name: "delete not found", get: item, del: kexec.MockResponse{Stderr: []byte("Not found."), ExitCode: 1}, wantIs: backend.ErrNotFound, wantDel: true},
		{name: "delete other exit", get: item, del: kexec.MockResponse{Stderr: []byte("kaboom detail"), ExitCode: 5}, wantSub: "bw exited 5", wantDel: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &kexec.MockRunner{Responses: map[string]kexec.MockResponse{
				argKey(fakeBWBin, "get", "item", "svc"):     tc.get,
				argKey(fakeBWBin, "delete", "item", "it-7"): tc.del,
			}}
			b := bkBWOpen(t, runner, bw.Options{})
			err := b.Delete(context.Background(), "default/svc/api_key")
			if tc.wantIs == nil && tc.wantSub == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				if tc.wantIs != nil {
					assert.ErrorIs(t, err, tc.wantIs)
				}
				assert.Contains(t, err.Error(), tc.wantSub)
				assert.NotContains(t, err.Error(), "kaboom detail")
			}
			deleted := false
			for _, c := range runner.Calls {
				if c.Args[0] == "delete" {
					deleted = true
					assert.Equal(t, []string{"delete", "item", "it-7"}, c.Args)
				}
			}
			assert.Equal(t, tc.wantDel, deleted)
		})
	}
}

func TestBWDelete_InvalidPath(t *testing.T) {
	b := bkBWOpen(t, &kexec.MockRunner{}, bw.Options{})
	err := b.Delete(context.Background(), "x")
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "bw Delete:"))
}

func TestBWDelete_EvictsCachedItem(t *testing.T) {
	runner := &kexec.MockRunner{Responses: map[string]kexec.MockResponse{
		argKey(fakeBWBin, "get", "item", "svc"): {Stdout: []byte(`{"id":"it-7","name":"svc","fields":[{"name":"api_key","value":"one","type":1}]}`)},
	}}
	b := bkBWOpen(t, runner, bw.Options{})
	ctx := context.Background()

	got, _, err := b.Get(ctx, "default/svc/api_key")
	require.NoError(t, err)
	assert.Equal(t, "one", string(got))
	// Mutating the returned copy must not affect the cache.
	got[0] = 'X'
	again, _, err := b.Get(ctx, "default/svc/api_key")
	require.NoError(t, err)
	assert.Equal(t, "one", string(again))
	gets := 0
	for _, c := range runner.Calls {
		if c.Args[0] == "get" {
			gets++
		}
	}
	assert.Equal(t, 1, gets, "second Get should be served from cache")

	require.NoError(t, b.Delete(ctx, "default/svc/api_key"))
	_, _, err = b.Get(ctx, "default/svc/api_key")
	require.NoError(t, err)
	gets = 0
	for _, c := range runner.Calls {
		if c.Args[0] == "get" {
			gets++
		}
	}
	assert.Equal(t, 3, gets, "Delete must evict the cache entry")
}

func (r *bkBWVerbRunner) RunEnv(ctx context.Context, name string, args []string, stdin []byte, _ []string) ([]byte, []byte, int, error) {
	return r.Run(ctx, name, args, stdin)
}
