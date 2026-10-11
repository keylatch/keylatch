package keeper_test

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
	"github.com/keylatch/keylatch/internal/backend/keeper"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/vault/meta"
)

const bkKPScript = `#!/bin/sh
PATH=/usr/bin:/bin
d="$(dirname "$0")"
printf '%s\n' "$*" >> "$d/argv.log"
case "$1" in
add)
  cat > "$d/stdin.bin"
  exit 0 ;;
get)
  if [ "$3" = "keylatch/app/token" ]; then
    printf '{"record_uid":"rec-1","title":"%s","password":"%s"}' "$3" "$(cat "$d/stdin.bin")"
    exit 0
  fi
  echo "record not found" >&2
  exit 1 ;;
ls)
  printf '[{"record_uid":"rec-1","title":"keylatch/app/token"},{"record_uid":"rec-2","title":"other/x"},{"record_uid":"rec-3","title":"keylatch/db/pw"}]'
  exit 0 ;;
delete)
  echo "Not logged in to vault.example" >&2
  exit 1 ;;
esac
exit 2
`

// bkKPFakeCLI installs a fake CLI under binName as the only binary on PATH and returns its directory.
func bkKPFakeCLI(t *testing.T, binName string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake CLI requires a POSIX shell")
	}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, binName), []byte(bkKPScript), 0o700)) //nolint:gosec // test executable
	t.Setenv("PATH", dir)
	return dir
}

func bkKPFactory(t *testing.T) backend.Factory {
	t.Helper()
	f, ok := backend.Default.Get("keeper")
	require.True(t, ok, "keeper must self-register")
	return f
}

func TestKeeperFakeCLI_RoundTripViaFactory(t *testing.T) {
	dir := bkKPFakeCLI(t, "keeper")
	kp, err := keeper.Open(keeper.Options{AccountUID: "acct-7", Runner: kexec.DefaultRunner})
	require.NoError(t, err)
	assert.Equal(t, "keeper", kp.Name())
	assert.Equal(t, []backend.Capability{backend.CapList}, kp.Capabilities())
	assert.Equal(t, "keeper:acct-7", kp.ID())

	ctx := context.Background()
	secret := "kp-" + strings.Repeat("w", 20)
	require.NoError(t, kp.Set(ctx, "app/token", []byte(secret), backend.Meta{}))

	argv, err := os.ReadFile(filepath.Join(dir, "argv.log"))
	require.NoError(t, err)
	assert.NotContains(t, string(argv), secret, "secret must never reach argv")
	assert.Contains(t, string(argv), "add --title keylatch/app/token --pass - --folder keylatch")
	stdin, err := os.ReadFile(filepath.Join(dir, "stdin.bin"))
	require.NoError(t, err)
	assert.Equal(t, secret, string(stdin))

	val, m, err := kp.Get(ctx, "app/token")
	require.NoError(t, err)
	assert.Equal(t, secret, string(val))
	assert.Equal(t, backend.ID("rec-1"), m.Accessor)

	_, _, err = kp.Get(ctx, "app/token")
	require.NoError(t, err)
	argv, err = os.ReadFile(filepath.Join(dir, "argv.log"))
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(string(argv), "get --format=json"), "second Get must be served from cache")

	_, _, err = kp.Get(ctx, "app/missing")
	assert.ErrorIs(t, err, backend.ErrNotFound)

	entries, err := kp.List(ctx, "db/")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "db/pw", entries[0].Path)
	assert.Equal(t, backend.ID("rec-3"), entries[0].Accessor)

	err = kp.Delete(ctx, "app/token")
	assert.ErrorIs(t, err, backend.ErrLocked)
	assert.NotContains(t, err.Error(), "vault.example", "raw stderr must not leak")

	require.NoError(t, kp.Close())
	assert.Equal(t, make([]byte, len(secret)), val, "Close must zero cached value bytes")
}

func TestKeeperFakeCLI_FallsBackToKsm(t *testing.T) {
	bkKPFakeCLI(t, "ksm")
	b, err := keeper.Open(keeper.Options{Runner: kexec.DefaultRunner})
	require.NoError(t, err)
	entries, err := b.List(context.Background(), "")
	require.NoError(t, err)
	assert.Len(t, entries, 2)
	assert.Equal(t, "keeper:default", b.ID())
}

func TestKeeperFakeCLI_OpenAndFactoryErrors(t *testing.T) {
	bkKPFakeCLI(t, "keeper")

	_, err := bkKPFactory(t)(context.Background(), backend.BackendConfig{Settings: map[string]interface{}{"account_uid": "acct-7"}})
	assert.ErrorIs(t, err, backend.ErrUnavailable, "the factory refuses keeper in this release")

	_, err = keeper.Open(keeper.Options{Bin: filepath.Join(t.TempDir(), "k"), Runner: kexec.DefaultRunner})
	require.NoError(t, err)

	t.Setenv("PATH", t.TempDir())
	_, err = keeper.Open(keeper.Options{Runner: kexec.DefaultRunner})
	assert.ErrorIs(t, err, backend.ErrUnavailable)
}

func TestKeeper_ErrorMapping(t *testing.T) {
	runnerErr := errors.New("spawn failed")
	cases := []struct {
		name string
		resp kexec.MockResponse
		call func(*keeper.KeeperBackend) error
		want error
		msg  string
	}{
		{"get runner error", kexec.MockResponse{Err: runnerErr}, bkKPGet, runnerErr, "runner error"},
		{"get generic failure", kexec.MockResponse{ExitCode: 3, Stderr: []byte("boom")}, bkKPGet, backend.ErrUnavailable, "get failed"},
		{"get bad json", kexec.MockResponse{Stdout: []byte("{nope")}, bkKPGet, backend.ErrUnavailable, "parse"},
		{"set runner error", kexec.MockResponse{Err: runnerErr}, bkKPSet, runnerErr, "runner error"},
		{"set generic failure", kexec.MockResponse{ExitCode: 1, Stderr: []byte("disk full")}, bkKPSet, backend.ErrUnavailable, "set failed"},
		{"delete runner error", kexec.MockResponse{Err: runnerErr}, bkKPDelete, runnerErr, "runner error"},
		{"delete auth", kexec.MockResponse{ExitCode: 1, Stderr: []byte("Login required")}, bkKPDelete, backend.ErrLocked, "keeper login"},
		{"delete generic failure", kexec.MockResponse{ExitCode: 1, Stderr: []byte("boom")}, bkKPDelete, backend.ErrUnavailable, "delete failed"},
		{"list runner error", kexec.MockResponse{Err: runnerErr}, bkKPList, runnerErr, "runner error"},
		{"list auth", kexec.MockResponse{ExitCode: 1, Stderr: []byte("authentication failed")}, bkKPList, backend.ErrLocked, "keeper login"},
		{"list generic failure", kexec.MockResponse{ExitCode: 1, Stderr: []byte("boom")}, bkKPList, backend.ErrUnavailable, "list failed"},
		{"list bad json", kexec.MockResponse{Stdout: []byte("[{")}, bkKPList, nil, "decode list response"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := keeper.Open(keeper.Options{Bin: "/fake/keeper", Runner: &bkKPAnyRunner{resp: tc.resp}})
			require.NoError(t, err)
			err = tc.call(b)
			require.Error(t, err)
			if tc.want != nil {
				assert.ErrorIs(t, err, tc.want)
			}
			assert.Contains(t, err.Error(), tc.msg)
		})
	}
}

func TestKeeper_GetHonoursCancelledContext(t *testing.T) {
	release := make(chan struct{})
	b, err := keeper.Open(keeper.Options{Bin: "/fake/keeper", Runner: &bkKPBlockingRunner{release: release}})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = b.Get(ctx, "app/token")
	close(release)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestKeeper_VersionedOperationsUnsupported(t *testing.T) {
	b, err := keeper.Open(keeper.Options{Bin: "/fake/keeper", Runner: &kexec.MockRunner{}})
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

func bkKPGet(b *keeper.KeeperBackend) error {
	_, _, err := b.Get(context.Background(), "app/token")
	return err
}

func bkKPSet(b *keeper.KeeperBackend) error {
	return b.Set(context.Background(), "app/token", []byte("v"), backend.Meta{})
}

func bkKPDelete(b *keeper.KeeperBackend) error {
	return b.Delete(context.Background(), "app/token")
}

func bkKPList(b *keeper.KeeperBackend) error {
	_, err := b.List(context.Background(), "")
	return err
}

type bkKPAnyRunner struct{ resp kexec.MockResponse }

func (r *bkKPAnyRunner) Run(_ context.Context, _ string, _ []string, _ []byte) ([]byte, []byte, int, error) {
	return r.resp.Stdout, r.resp.Stderr, r.resp.ExitCode, r.resp.Err
}

type bkKPBlockingRunner struct{ release chan struct{} }

func (r *bkKPBlockingRunner) Run(_ context.Context, _ string, _ []string, _ []byte) ([]byte, []byte, int, error) {
	<-r.release
	return nil, nil, 1, nil
}

func (r *bkKPAnyRunner) RunEnv(ctx context.Context, name string, args []string, stdin []byte, _ []string) ([]byte, []byte, int, error) {
	return r.Run(ctx, name, args, stdin)
}

func (r *bkKPBlockingRunner) RunEnv(ctx context.Context, name string, args []string, stdin []byte, _ []string) ([]byte, []byte, int, error) {
	return r.Run(ctx, name, args, stdin)
}
