package op_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/op"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

const bkOPScript = `#!/bin/sh
PATH=/usr/bin:/bin
d="$(dirname "$0")"
printf '%s\n' "$*" >> "$d/argv.log"
case "$1 $2" in
"item get")
  case "$3" in
  github)
    printf '{"id":"itm-1","title":"github","updated_at":"2026-01-02T03:04:05Z","fields":[{"id":"f1","label":"token","type":"CONCEALED","value":"%s"}]}' "$(cat "$d/value.txt")"
    exit 0 ;;
  single)
    printf '[{"id":"itm-2","title":"single","fields":[{"id":"f1","label":"password","value":"one"}]}]'
    exit 0 ;;
  none)
    printf '[]'
    exit 0 ;;
  locked)
    echo "[ERROR] You are not currently signed in. Please run op signin --account corp.example" >&2
    exit 1 ;;
  esac
  echo "[ERROR] \"$3\" isn't an item in the \"Keylatch\" vault." >&2
  exit 1 ;;
"item list")
  printf '[{"id":"itm-1","title":"github","fields":[{"id":"f1","label":"token"},{"id":"f2","label":"user"}]},{"id":"itm-3","title":"stripe","fields":[{"id":"f1","label":"api_key"}]}]'
  exit 0 ;;
"item delete")
  echo "[ERROR] internal failure talking to corp.example" >&2
  exit 1 ;;
esac
exit 2
`

// bkOPFakeCLI installs a fake op as the only binary on PATH and returns its directory.
func bkOPFakeCLI(t *testing.T, value string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake CLI requires a POSIX shell")
	}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "op"), []byte(bkOPScript), 0o700)) //nolint:gosec // test executable
	require.NoError(t, os.WriteFile(filepath.Join(dir, "value.txt"), []byte(value), 0o600))
	t.Setenv("PATH", dir)
	return dir
}

func bkOPFactory(t *testing.T) backend.Factory {
	t.Helper()
	f, ok := backend.Default.Get("op")
	require.True(t, ok, "op must self-register")
	return f
}

func TestOPFakeCLI_ReadPathsViaFactory(t *testing.T) {
	secret := "op-" + strings.Repeat("z", 24)
	dir := bkOPFakeCLI(t, secret)
	b, err := bkOPFactory(t)(context.Background(), backend.BackendConfig{Settings: map[string]interface{}{"vault": "Keylatch"}})
	require.NoError(t, err)
	assert.Equal(t, "op:Keylatch", b.(*op.OnePasswordBackend).ID())
	ctx := context.Background()

	val, m, err := b.Get(ctx, "default/github/token")
	require.NoError(t, err)
	assert.Equal(t, secret, string(val))
	assert.Equal(t, backend.ID("itm-1"), m.Accessor)
	assert.Equal(t, 2026, m.UpdatedAt.Year())

	_, _, err = b.Get(ctx, "default/github/token")
	require.NoError(t, err)
	argv, err := os.ReadFile(filepath.Join(dir, "argv.log"))
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(string(argv), "item get github"), "repeat Get must hit the item cache")

	_, _, err = b.Get(ctx, "default/github/missing_field")
	assert.ErrorIs(t, err, backend.ErrNotFound)

	val, _, err = b.Get(ctx, "single/password")
	require.NoError(t, err, "a one-element array response is accepted as the item")
	assert.Equal(t, "one", string(val))

	_, _, err = b.Get(ctx, "default/none/password")
	assert.ErrorIs(t, err, backend.ErrNotFound)

	_, _, err = b.Get(ctx, "default/absent/password")
	assert.ErrorIs(t, err, backend.ErrNotFound)

	_, _, err = b.Get(ctx, "default/locked/password")
	assert.ErrorIs(t, err, backend.ErrLocked)
	assert.NotContains(t, err.Error(), "corp.example", "raw stderr must not leak")
	assert.Contains(t, err.Error(), "op signin")

	entries, err := b.List(ctx, "default/github/")
	require.NoError(t, err)
	require.Len(t, entries, 2)
	for _, e := range entries {
		assert.True(t, strings.HasPrefix(e.Path, "default/github/"))
		assert.Equal(t, backend.ID("itm-1"), e.Accessor)
	}

	err = b.Delete(ctx, "default/github/token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "op exited 1")
	assert.NotContains(t, err.Error(), "corp.example", "raw stderr must not leak")
	require.NoError(t, b.Close())
}

func TestOPFakeCLI_FactorySettings(t *testing.T) {
	bkOPFakeCLI(t, "x")
	f := bkOPFactory(t)
	ctx := context.Background()

	b, err := f(ctx, backend.BackendConfig{Settings: map[string]interface{}{"env": func(string) string { return "" }}})
	require.NoError(t, err)
	assert.Equal(t, "op:Keylatch", b.(*op.OnePasswordBackend).ID(), "vault defaults to Keylatch")

	b, err = f(ctx, backend.BackendConfig{Settings: map[string]interface{}{"env": llmcontext.Lookup(func(string) string { return "" }), "vault": "Team"}})
	require.NoError(t, err)
	assert.Equal(t, "op:Team", b.(*op.OnePasswordBackend).ID())

	_, err = f(ctx, backend.BackendConfig{Settings: map[string]interface{}{"env": 42}})
	require.NoError(t, err, "non-function env values are ignored")

	_, err = f(ctx, backend.BackendConfig{Settings: map[string]interface{}{"account": "x"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid settings")

	_, err = f(ctx, backend.BackendConfig{Settings: map[string]interface{}{"bin": filepath.Join(t.TempDir(), "op")}})
	require.NoError(t, err)

	t.Setenv("PATH", t.TempDir())
	_, err = f(ctx, backend.BackendConfig{})
	assert.ErrorIs(t, err, backend.ErrUnavailable)
}

// bkOPScripted answers each call by matching the joined argv against substrings, in order.
type bkOPScripted struct {
	rules []bkOPRule
	calls [][]string
}

type bkOPRule struct {
	match string
	resp  kexec.MockResponse
}

func (r *bkOPScripted) Run(_ context.Context, _ string, args []string, _ []byte) ([]byte, []byte, int, error) {
	r.calls = append(r.calls, args)
	joined := strings.Join(args, " ")
	for _, rule := range r.rules {
		if strings.Contains(joined, rule.match) {
			return rule.resp.Stdout, rule.resp.Stderr, rule.resp.ExitCode, rule.resp.Err
		}
	}
	return nil, []byte("unexpected"), 99, nil
}

func bkOPOpen(t *testing.T, rules ...bkOPRule) (*op.OnePasswordBackend, *bkOPScripted) {
	t.Helper()
	r := &bkOPScripted{rules: rules}
	b, err := op.Open(op.Options{Bin: "/fake/op", Runner: r})
	require.NoError(t, err)
	return b, r
}

func TestOP_InvalidPathsRejected(t *testing.T) {
	b, r := bkOPOpen(t)
	ctx := context.Background()
	_, _, err := b.Get(ctx, "lonely")
	assert.ErrorContains(t, err, "invalid canonical path")
	assert.ErrorContains(t, b.Set(ctx, "lonely", []byte("v"), backend.Meta{}), "invalid canonical path")
	assert.ErrorContains(t, b.Delete(ctx, "lonely"), "invalid canonical path")
	assert.Empty(t, r.calls, "invalid paths must not reach the CLI")
}

func TestOP_SetEditsExistingItem(t *testing.T) {
	b, r := bkOPOpen(t,
		bkOPRule{"item get", kexec.MockResponse{Stdout: []byte(`{"id":"itm-1","title":"github","fields":[{"label":"token","value":"v"}]}`)}},
		bkOPRule{"item edit", kexec.MockResponse{Stdout: []byte("not json")}},
	)
	require.NoError(t, b.Set(context.Background(), "default/github/token", []byte("v"), backend.Meta{}),
		"an unparseable edit response is not fatal when the item reads back with the value")
	require.Len(t, r.calls, 3, "existence check, edit, read back")
	assert.Equal(t, []string{"item", "edit", "github", "--template=/dev/stdin", "--vault=Keylatch", "--format=json"}, r.calls[1])
}

func TestOP_SetFailsWhenItemDoesNotHoldWrittenValue(t *testing.T) {
	b, _ := bkOPOpen(t,
		bkOPRule{"item get", kexec.MockResponse{Stdout: []byte(`{"id":"itm-1","title":"github","fields":[{"label":"token","value":"other"}]}`)}},
		bkOPRule{"item edit", kexec.MockResponse{Stdout: []byte("{}")}},
	)
	err := b.Set(context.Background(), "default/github/token", []byte("v"), backend.Meta{})
	assert.ErrorIs(t, err, op.ErrWriteNotApplied)
	assert.NotContains(t, err.Error(), "other")
}

func TestOP_SetErrors(t *testing.T) {
	runnerErr := errors.New("spawn failed")
	missing := bkOPRule{"item get", kexec.MockResponse{ExitCode: 1, Stderr: []byte("item not found")}}
	cases := []struct {
		name string
		resp kexec.MockResponse
		want error
		msg  string
	}{
		{"runner error", kexec.MockResponse{Err: runnerErr}, runnerErr, "runner error"},
		{"auth", kexec.MockResponse{ExitCode: 1, Stderr: []byte("session expired at corp.example")}, backend.ErrLocked, "op signin"},
		{"generic", kexec.MockResponse{ExitCode: 4, Stderr: []byte("corp.example exploded")}, nil, "op exited 4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := bkOPOpen(t, missing, bkOPRule{"item create", tc.resp})
			err := b.Set(context.Background(), "default/github/token", []byte("v"), backend.Meta{})
			require.Error(t, err)
			if tc.want != nil {
				assert.ErrorIs(t, err, tc.want)
			}
			assert.Contains(t, err.Error(), tc.msg)
			assert.NotContains(t, err.Error(), "corp.example")
		})
	}
}

func TestOP_DeleteAndListErrors(t *testing.T) {
	runnerErr := errors.New("spawn failed")
	ctx := context.Background()

	b, _ := bkOPOpen(t, bkOPRule{"item delete", kexec.MockResponse{Err: runnerErr}})
	assert.ErrorIs(t, b.Delete(ctx, "default/github/token"), runnerErr)

	b, _ = bkOPOpen(t, bkOPRule{"item list", kexec.MockResponse{Err: runnerErr}})
	_, err := b.List(ctx, "")
	assert.ErrorIs(t, err, runnerErr)

	b, _ = bkOPOpen(t, bkOPRule{"item list", kexec.MockResponse{ExitCode: 1, Stderr: []byte("Authorization required")}})
	_, err = b.List(ctx, "")
	assert.ErrorIs(t, err, backend.ErrLocked)

	b, _ = bkOPOpen(t, bkOPRule{"item list", kexec.MockResponse{ExitCode: 6, Stderr: []byte("corp.example")}})
	_, err = b.List(ctx, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "op exited 6")
	assert.NotContains(t, err.Error(), "corp.example")

	b, _ = bkOPOpen(t, bkOPRule{"item list", kexec.MockResponse{Stdout: []byte("[{")}})
	_, err = b.List(ctx, "")
	assert.ErrorContains(t, err, "decode response")
}

func TestOP_GetRunnerErrorAndCancellation(t *testing.T) {
	runnerErr := errors.New("spawn failed")
	b, _ := bkOPOpen(t, bkOPRule{"item get", kexec.MockResponse{Err: runnerErr}})
	_, _, err := b.Get(context.Background(), "default/github/token")
	assert.ErrorIs(t, err, runnerErr)

	release := make(chan struct{})
	blocked, err := op.Open(op.Options{Bin: "/fake/op", Runner: &bkOPBlockingRunner{release: release}})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = blocked.Get(ctx, "default/github/token")
	close(release)
	assert.ErrorIs(t, err, context.Canceled)
}

type bkOPBlockingRunner struct{ release chan struct{} }

func (r *bkOPBlockingRunner) Run(_ context.Context, _ string, _ []string, _ []byte) ([]byte, []byte, int, error) {
	<-r.release
	return nil, nil, 1, nil
}

func TestOP_GetAmbiguousStderr(t *testing.T) {
	b, _ := bkOPOpen(t, bkOPRule{"item get", kexec.MockResponse{ExitCode: 1, Stderr: []byte("More than one item matches \"github\" in corp.example")}})
	_, _, err := b.Get(context.Background(), "default/github/token")
	var amb op.ErrAmbiguous
	require.ErrorAs(t, err, &amb)
	assert.Equal(t, "github", amb.Connection)
	assert.Contains(t, err.Error(), "--account")
	assert.NotContains(t, err.Error(), "corp.example")
}

func (r *bkOPScripted) RunEnv(ctx context.Context, name string, args []string, stdin []byte, _ []string) ([]byte, []byte, int, error) {
	return r.Run(ctx, name, args, stdin)
}

func (r *bkOPBlockingRunner) RunEnv(ctx context.Context, name string, args []string, stdin []byte, _ []string) ([]byte, []byte, int, error) {
	return r.Run(ctx, name, args, stdin)
}
