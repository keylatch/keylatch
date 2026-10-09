package protonpass_test

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
	"github.com/keylatch/keylatch/internal/backend/protonpass"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/vault/meta"
)

const bkPPScript = `#!/bin/sh
PATH=/usr/bin:/bin
d="$(dirname "$0")"
printf '%s\n' "$*" >> "$d/argv.log"
case "$1 $2" in
"item create")
  cat > "$d/stdin.bin"
  exit 0 ;;
"item get")
  if [ "$3" = "keylatch/app/token" ]; then
    printf '{"metadata":{"name":"%s"},"content":{"note":"%s"}}' "$3" "$(cat "$d/stdin.bin")"
    exit 0
  fi
  echo "error: item not found" >&2
  exit 1 ;;
"item list")
  printf '[{"ItemID":"1","name":"keylatch/app/token"},{"ItemID":"2","name":"other/x"},{"ItemID":"3","name":"keylatch/db/pw"}]'
  exit 0 ;;
"item delete")
  echo "session expired for user" >&2
  exit 1 ;;
esac
exit 2
`

// bkPPFakeCLI installs a fake pass-cli as the only binary on PATH and returns its directory.
func bkPPFakeCLI(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake CLI requires a POSIX shell")
	}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pass-cli"), []byte(bkPPScript), 0o700)) //nolint:gosec // test executable
	t.Setenv("PATH", dir)
	return dir
}

func bkPPFactory(t *testing.T) backend.Factory {
	t.Helper()
	f, ok := backend.Default.Get("proton-pass")
	require.True(t, ok, "proton-pass must self-register")
	return f
}

func TestProtonPassFakeCLI_RoundTripViaFactory(t *testing.T) {
	dir := bkPPFakeCLI(t)
	pp, err := protonpass.Open(protonpass.Options{Vault: "work", Runner: kexec.DefaultRunner})
	require.NoError(t, err)
	assert.Equal(t, "proton-pass", pp.Name())
	assert.Equal(t, []backend.Capability{backend.CapList, backend.CapNetworkedFetch}, pp.Capabilities())
	assert.Equal(t, "proton-pass:work", pp.ID())

	ctx := context.Background()
	secret := "pp-" + strings.Repeat("v", 20)
	require.NoError(t, pp.Set(ctx, "app/token", []byte(secret), backend.Meta{}))

	argv, err := os.ReadFile(filepath.Join(dir, "argv.log"))
	require.NoError(t, err)
	assert.NotContains(t, string(argv), secret, "secret must never reach argv")
	stdin, err := os.ReadFile(filepath.Join(dir, "stdin.bin"))
	require.NoError(t, err)
	assert.Equal(t, secret, string(stdin))

	val, meta, err := pp.Get(ctx, "app/token")
	require.NoError(t, err)
	assert.Equal(t, secret, string(val))
	assert.Equal(t, "app/token", meta.Path)

	again, _, err := pp.Get(ctx, "app/token")
	require.NoError(t, err)
	assert.Equal(t, secret, string(again))
	argv, err = os.ReadFile(filepath.Join(dir, "argv.log"))
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(string(argv), "item get"), "second Get must be served from cache")

	_, _, err = pp.Get(ctx, "app/missing")
	assert.ErrorIs(t, err, backend.ErrNotFound)

	entries, err := pp.List(ctx, "db/")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "db/pw", entries[0].Path)
	assert.True(t, entries[0].Exists)

	err = pp.Delete(ctx, "app/token")
	assert.ErrorIs(t, err, backend.ErrLocked)
	assert.NotContains(t, err.Error(), "session expired for user", "raw stderr must not leak")

	require.NoError(t, pp.Close())
	assert.Equal(t, make([]byte, len(secret)), val, "Close must zero cached value bytes")
	_, _, err = pp.Get(ctx, "app/token")
	require.NoError(t, err)
	argv, err = os.ReadFile(filepath.Join(dir, "argv.log"))
	require.NoError(t, err)
	assert.Equal(t, 2, strings.Count(string(argv), "item get keylatch/app/token"), "Close must evict the cache")
}

func TestProtonPassFakeCLI_OpenAndFactoryErrors(t *testing.T) {
	bkPPFakeCLI(t)

	_, err := bkPPFactory(t)(context.Background(), backend.BackendConfig{Settings: map[string]interface{}{"vault": "work"}})
	assert.ErrorIs(t, err, backend.ErrUnavailable, "the factory refuses proton-pass in this release")

	explicit := filepath.Join(t.TempDir(), "custom-pass")
	b, err := protonpass.Open(protonpass.Options{Bin: explicit, ItemPrefix: "kl/", Runner: kexec.DefaultRunner})
	require.NoError(t, err)
	assert.Equal(t, "proton-pass:default", b.ID())

	t.Setenv("PATH", t.TempDir())
	_, err = protonpass.Open(protonpass.Options{Runner: kexec.DefaultRunner})
	assert.ErrorIs(t, err, backend.ErrUnavailable)
}

func TestProtonPass_ErrorMapping(t *testing.T) {
	const bin = "/fake/pass-cli"
	runnerErr := errors.New("spawn failed")
	cases := []struct {
		name string
		resp kexec.MockResponse
		call func(*protonpass.ProtonPassBackend) error
		want error
		msg  string
	}{
		{"get runner error", kexec.MockResponse{Err: runnerErr}, bkPPGet, runnerErr, "runner error"},
		{"get generic failure", kexec.MockResponse{ExitCode: 3, Stderr: []byte("boom")}, bkPPGet, backend.ErrUnavailable, "get failed"},
		{"get bad json", kexec.MockResponse{Stdout: []byte("{nope")}, bkPPGet, backend.ErrUnavailable, "parse"},
		{"set runner error", kexec.MockResponse{Err: runnerErr}, bkPPSet, runnerErr, "runner error"},
		{"set generic failure", kexec.MockResponse{ExitCode: 1, Stderr: []byte("disk full")}, bkPPSet, backend.ErrUnavailable, "set failed"},
		{"delete runner error", kexec.MockResponse{Err: runnerErr}, bkPPDelete, runnerErr, "runner error"},
		{"delete auth", kexec.MockResponse{ExitCode: 1, Stderr: []byte("Unauthenticated")}, bkPPDelete, backend.ErrLocked, "auth login"},
		{"delete generic failure", kexec.MockResponse{ExitCode: 1, Stderr: []byte("boom")}, bkPPDelete, backend.ErrUnavailable, "delete failed"},
		{"list runner error", kexec.MockResponse{Err: runnerErr}, bkPPList, runnerErr, "runner error"},
		{"list auth", kexec.MockResponse{ExitCode: 1, Stderr: []byte("authentication required")}, bkPPList, backend.ErrLocked, "auth login"},
		{"list generic failure", kexec.MockResponse{ExitCode: 1, Stderr: []byte("boom")}, bkPPList, backend.ErrUnavailable, "list failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &bkPPAnyRunner{resp: tc.resp}
			b, err := protonpass.Open(protonpass.Options{Bin: bin, Runner: r})
			require.NoError(t, err)
			err = tc.call(b)
			require.Error(t, err)
			assert.ErrorIs(t, err, tc.want)
			assert.Contains(t, err.Error(), tc.msg)
		})
	}

	t.Run("list bad json", func(t *testing.T) {
		b, err := protonpass.Open(protonpass.Options{Bin: bin, Runner: &bkPPAnyRunner{resp: kexec.MockResponse{Stdout: []byte("[{")}}})
		require.NoError(t, err)
		_, err = b.List(context.Background(), "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decode list response")
	})
}

func TestProtonPass_GetHonoursCancelledContext(t *testing.T) {
	release := make(chan struct{})
	r := &bkPPBlockingRunner{release: release}
	b, err := protonpass.Open(protonpass.Options{Bin: "/fake/pass-cli", Runner: r})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = b.Get(ctx, "app/token")
	close(release)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestProtonPass_VersionedOperationsUnsupported(t *testing.T) {
	b, err := protonpass.Open(protonpass.Options{Bin: "/fake/pass-cli", Runner: &kexec.MockRunner{}})
	require.NoError(t, err)
	ctx := context.Background()
	_, err = b.GetMeta(ctx, "p")
	assert.ErrorIs(t, err, backend.ErrNotSupported)
	assert.ErrorIs(t, b.SetMeta(ctx, "p", meta.Meta{}), backend.ErrNotSupported)
	_, err = b.ListMeta(ctx, "p")
	assert.ErrorIs(t, err, backend.ErrNotSupported)
	_, err = b.GetVersioned(ctx, "p", 1)
	assert.ErrorIs(t, err, backend.ErrNotSupported)
	assert.ErrorIs(t, b.SetVersioned(ctx, "p", 1, []byte("v")), backend.ErrNotSupported)
	assert.ErrorIs(t, b.DeleteVersioned(ctx, "p", 1), backend.ErrNotSupported)
}

func bkPPGet(b *protonpass.ProtonPassBackend) error {
	_, _, err := b.Get(context.Background(), "app/token")
	return err
}

func bkPPSet(b *protonpass.ProtonPassBackend) error {
	return b.Set(context.Background(), "app/token", []byte("v"), backend.Meta{})
}

func bkPPDelete(b *protonpass.ProtonPassBackend) error {
	return b.Delete(context.Background(), "app/token")
}

func bkPPList(b *protonpass.ProtonPassBackend) error {
	_, err := b.List(context.Background(), "")
	return err
}

type bkPPAnyRunner struct{ resp kexec.MockResponse }

func (r *bkPPAnyRunner) Run(_ context.Context, _ string, _ []string, _ []byte) ([]byte, []byte, int, error) {
	return r.resp.Stdout, r.resp.Stderr, r.resp.ExitCode, r.resp.Err
}

type bkPPBlockingRunner struct{ release chan struct{} }

func (r *bkPPBlockingRunner) Run(_ context.Context, _ string, _ []string, _ []byte) ([]byte, []byte, int, error) {
	<-r.release
	return nil, nil, 1, nil
}

func (r *bkPPAnyRunner) RunEnv(ctx context.Context, name string, args []string, stdin []byte, _ []string) ([]byte, []byte, int, error) {
	return r.Run(ctx, name, args, stdin)
}

func (r *bkPPBlockingRunner) RunEnv(ctx context.Context, name string, args []string, stdin []byte, _ []string) ([]byte, []byte, int, error) {
	return r.Run(ctx, name, args, stdin)
}
