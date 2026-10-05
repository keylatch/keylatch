package bw_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/bw"
	kexec "github.com/keylatch/keylatch/internal/exec"
)

func TestBWGet_ErrorMapping(t *testing.T) {
	cases := []struct {
		name    string
		resp    map[string]kexec.MockResponse
		wantIs  error
		wantSub string
	}{
		{"runner error", map[string]kexec.MockResponse{"get": {Err: errors.New("spawn")}}, nil, "runner error"},
		{"not found", map[string]kexec.MockResponse{"get": {Stderr: []byte("No items found."), ExitCode: 1}}, backend.ErrNotFound, "svc"},
		{"generic exit", map[string]kexec.MockResponse{"get": {Stderr: []byte("raw stderr detail"), ExitCode: 9}}, nil, "get item exited 9"},
		{"bad json", map[string]kexec.MockResponse{"get": {Stdout: []byte("{nope")}}, nil, "decode item"},
		{"locked, status unlocked", map[string]kexec.MockResponse{
			"get":    {Stderr: []byte("Invalid session"), ExitCode: 1},
			"status": {Stdout: []byte(`{"status":"unlocked"}`)},
		}, backend.ErrLocked, "BW_SESSION"},
		{"locked, status fails", map[string]kexec.MockResponse{
			"get":    {Stderr: []byte("Session key is invalid."), ExitCode: 1},
			"status": {ExitCode: 1},
		}, backend.ErrLocked, "BW_SESSION"},
		{"locked, status garbage", map[string]kexec.MockResponse{
			"get":    {Stderr: []byte("Vault is locked."), ExitCode: 1},
			"status": {Stdout: []byte("garbage")},
		}, backend.ErrLocked, "BW_SESSION"},
		{"locked, status unauthenticated", map[string]kexec.MockResponse{
			"get":    {Stderr: []byte("Not logged in."), ExitCode: 1},
			"status": {Stdout: []byte(`{"status":"unauthenticated"}`)},
		}, backend.ErrLocked, "BW_SESSION"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &bkBWVerbRunner{resp: tc.resp}
			b := bkBWOpen(t, runner, bw.Options{})
			val, _, err := b.Get(context.Background(), "default/svc/api_key")
			require.Error(t, err)
			assert.Nil(t, val)
			if tc.wantIs != nil {
				assert.ErrorIs(t, err, tc.wantIs)
			}
			assert.Contains(t, err.Error(), tc.wantSub)
			assert.NotContains(t, err.Error(), "raw stderr detail")
		})
	}
}

func TestBWGet_InvalidPath(t *testing.T) {
	runner := &bkBWVerbRunner{}
	b := bkBWOpen(t, runner, bw.Options{})
	_, _, err := b.Get(context.Background(), "single")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid canonical path")
	assert.Empty(t, runner.calls, "no subprocess for an invalid path")
}

func TestBWGet_TwoPartPathAndRFC3339Revision(t *testing.T) {
	runner := &bkBWVerbRunner{resp: map[string]kexec.MockResponse{
		"get": {Stdout: []byte(`{"id":"it-2","name":"svc","fields":[{"name":"api_key","value":"v1","type":1}],"revisionDate":"2026-01-02T03:04:05Z"}`)},
	}}
	b := bkBWOpen(t, runner, bw.Options{})
	val, meta, err := b.Get(context.Background(), "svc/api_key")
	require.NoError(t, err)
	assert.Equal(t, "v1", string(val))
	assert.Equal(t, backend.ID("it-2"), meta.Accessor)
	assert.Equal(t, "svc/api_key", meta.Path)
	assert.True(t, meta.UpdatedAt.Equal(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)), "UpdatedAt=%v", meta.UpdatedAt)
	assert.Equal(t, []string{"get", "item", "svc"}, runner.calls[0])
}

func TestBWGet_AutoSyncErrors(t *testing.T) {
	cases := []struct {
		name    string
		sync    kexec.MockResponse
		wantIs  error
		wantSub string
	}{
		{"runner error", kexec.MockResponse{Err: errors.New("spawn")}, nil, "bw sync: runner error"},
		{"locked", kexec.MockResponse{Stderr: []byte("Vault is locked."), ExitCode: 1}, backend.ErrLocked, "BW_SESSION"},
		{"other exit", kexec.MockResponse{ExitCode: 6}, nil, "bw sync: exited 6"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &bkBWVerbRunner{resp: map[string]kexec.MockResponse{"sync": tc.sync}}
			b := bkBWOpen(t, runner, bw.Options{AutoSync: true})

			_, _, err := b.Get(context.Background(), "default/svc/api_key")
			require.Error(t, err)
			if tc.wantIs != nil {
				assert.ErrorIs(t, err, tc.wantIs)
			}
			assert.Contains(t, err.Error(), tc.wantSub)

			_, err = b.List(context.Background(), "")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)

			for _, c := range runner.calls {
				assert.Equal(t, "sync", c[0], "nothing may run after a failed sync")
			}
		})
	}
}

func TestBWGet_AutoSyncSuccessThenFetch(t *testing.T) {
	runner := &bkBWVerbRunner{resp: map[string]kexec.MockResponse{
		"get": {Stdout: []byte(`{"id":"i","name":"svc","fields":[{"name":"api_key","value":"x","type":1}]}`)},
	}}
	b := bkBWOpen(t, runner, bw.Options{AutoSync: true})
	val, _, err := b.Get(context.Background(), "default/svc/api_key")
	require.NoError(t, err)
	assert.Equal(t, "x", string(val))
	require.Len(t, runner.calls, 2)
	assert.Equal(t, "sync", runner.calls[0][0])
	assert.Equal(t, "get", runner.calls[1][0])
}

// bkBWBlockingRunner blocks every call until release is closed.
type bkBWBlockingRunner struct {
	started chan struct{}
	release chan struct{}
}

func (r *bkBWBlockingRunner) Run(_ context.Context, _ string, _ []string, _ []byte) ([]byte, []byte, int, error) {
	r.started <- struct{}{}
	<-r.release
	return []byte(`{"id":"i","name":"svc","fields":[]}`), nil, 0, nil
}

func TestBWGet_ContextCancelledWhileFetching(t *testing.T) {
	runner := &bkBWBlockingRunner{started: make(chan struct{}, 1), release: make(chan struct{})}
	b := bkBWOpen(t, runner, bw.Options{})

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, _, err := b.Get(ctx, "default/svc/api_key")
		errCh <- err
	}()
	select {
	case <-runner.started:
	case <-time.After(10 * time.Second):
		t.Fatal("fetch never started")
	}
	cancel()
	select {
	case err := <-errCh:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(10 * time.Second):
		t.Fatal("Get did not return after cancellation")
	}
	close(runner.release)
}

func TestBWList_ErrorMapping(t *testing.T) {
	cases := []struct {
		name    string
		resp    kexec.MockResponse
		wantIs  error
		wantSub string
	}{
		{"runner error", kexec.MockResponse{Err: errors.New("spawn")}, nil, "bw List: runner error"},
		{"locked", kexec.MockResponse{Stderr: []byte("You are not logged in."), ExitCode: 1}, backend.ErrLocked, "BW_SESSION"},
		{"other exit", kexec.MockResponse{Stderr: []byte("raw stderr detail"), ExitCode: 7}, nil, "bw exited 7"},
		{"bad json", kexec.MockResponse{Stdout: []byte("[{")}, nil, "decode response"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := bkBWOpen(t, &bkBWVerbRunner{resp: map[string]kexec.MockResponse{"list": tc.resp}}, bw.Options{})
			entries, err := b.List(context.Background(), "")
			require.Error(t, err)
			assert.Nil(t, entries)
			if tc.wantIs != nil {
				assert.ErrorIs(t, err, tc.wantIs)
			}
			assert.Contains(t, err.Error(), tc.wantSub)
			assert.NotContains(t, err.Error(), "raw stderr detail")
		})
	}
}

const bkBWListJSON = `[
 {"id":"a","name":"alpha","folderId":"f1","collectionIds":["c1"],"fields":[{"name":"api_key","value":"secretA","type":1},{"name":"url","value":"u","type":0}]},
 {"id":"b","name":"beta","folderId":null,"collectionIds":["c2"],"fields":[{"name":"api_key","value":"secretB","type":1}]},
 {"id":"c","name":"gamma","folderId":"","collectionIds":[],"fields":[{"name":"token","value":"secretC","type":1}]}
]`

func TestBWList_FiltersAndNeverReturnsValues(t *testing.T) {
	cases := []struct {
		name   string
		opts   bw.Options
		prefix string
		want   []string
	}{
		{"no filter", bw.Options{}, "", []string{"default/alpha/api_key", "default/alpha/url", "default/beta/api_key", "default/gamma/token"}},
		{"prefix", bw.Options{}, "default/alpha/", []string{"default/alpha/api_key", "default/alpha/url"}},
		{"collection", bw.Options{Collection: "c2"}, "", []string{"default/beta/api_key"}},
		{"collection unmatched", bw.Options{Collection: "zz"}, "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &bkBWVerbRunner{resp: map[string]kexec.MockResponse{"list": {Stdout: []byte(bkBWListJSON)}}}
			b := bkBWOpen(t, runner, tc.opts)
			entries, err := b.List(context.Background(), tc.prefix)
			require.NoError(t, err)
			var got []string
			for _, e := range entries {
				got = append(got, e.Path)
				assert.True(t, e.Exists)
				assert.Equal(t, "bw", e.Backend)
				assert.NotContains(t, e.Path, "secret")
				assert.NotContains(t, string(e.Accessor), "secret")
			}
			assert.Equal(t, tc.want, got)
			assert.Equal(t, []string{"list", "items", "--search=keylatch"}, runner.calls[0])
		})
	}
}

func (r *bkBWBlockingRunner) RunEnv(ctx context.Context, name string, args []string, stdin []byte, _ []string) ([]byte, []byte, int, error) {
	return r.Run(ctx, name, args, stdin)
}
