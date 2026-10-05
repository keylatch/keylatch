package lastpass_test

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
	"github.com/keylatch/keylatch/internal/backend/lastpass"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/vault/meta"
)

const bkLPScript = `#!/bin/sh
PATH=/usr/bin:/bin
d="$(dirname "$0")"
printf '%s\n' "$*" >> "$d/argv.log"
case "$1" in
add)
  cat > "$d/stdin.bin"
  exit 0 ;;
show)
  case "$4" in
  keylatch/app/token)
    printf '[{"id":"lp-1","name":"%s","password":"%s"}]' "$4" "$(sed -n 's/^Password: //p' "$d/stdin.bin")"
    exit 0 ;;
  keylatch/app/empty)
    printf '[]'
    exit 0 ;;
  esac
  echo "Error: Could not find specified account(s)." >&2
  exit 1 ;;
ls)
  printf '[{"id":"lp-1","name":"keylatch/app/token"},{"id":"lp-2","name":"other/x"},{"id":"lp-3","name":"keylatch/db/pw"}]'
  exit 0 ;;
rm)
  echo "Error: session at lastpass.example expired. Please login." >&2
  exit 1 ;;
esac
exit 2
`

// bkLPFakeCLI installs a fake lpass as the only binary on PATH and returns its directory.
func bkLPFakeCLI(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake CLI requires a POSIX shell")
	}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "lpass"), []byte(bkLPScript), 0o700)) //nolint:gosec // test executable
	t.Setenv("PATH", dir)
	return dir
}

func bkLPFactory(t *testing.T) backend.Factory {
	t.Helper()
	f, ok := backend.Default.Get("lastpass")
	require.True(t, ok, "lastpass must self-register")
	return f
}

func TestLastPassFakeCLI_RoundTripViaFactory(t *testing.T) {
	dir := bkLPFakeCLI(t)
	b, err := bkLPFactory(t)(context.Background(), backend.BackendConfig{Settings: map[string]interface{}{"username": "someone@example.com"}})
	require.NoError(t, err)
	lp := b.(*lastpass.LastPassBackend)
	assert.Equal(t, "lastpass", lp.Name())
	assert.Equal(t, []backend.Capability{backend.CapList}, lp.Capabilities())
	assert.NotContains(t, lp.ID(), "someone@example.com")

	ctx := context.Background()
	secret := "lp-" + strings.Repeat("q", 20)
	require.NoError(t, lp.Set(ctx, "app/token", []byte(secret), backend.Meta{}))

	argv, err := os.ReadFile(filepath.Join(dir, "argv.log"))
	require.NoError(t, err)
	assert.NotContains(t, string(argv), secret, "secret must never reach argv")
	stdin, err := os.ReadFile(filepath.Join(dir, "stdin.bin"))
	require.NoError(t, err)
	assert.Equal(t, "Username: keylatch\nPassword: "+secret+"\n", string(stdin))

	// An already-prefixed path must not be double-prefixed.
	val, m, err := lp.Get(ctx, "keylatch/app/token")
	require.NoError(t, err)
	assert.Equal(t, secret, string(val))
	assert.Equal(t, backend.ID("lp-1"), m.Accessor)
	assert.Equal(t, "lastpass", m.Backend)

	_, _, err = lp.Get(ctx, "app/empty")
	assert.ErrorIs(t, err, backend.ErrNotFound)

	_, _, err = lp.Get(ctx, "app/missing")
	assert.ErrorIs(t, err, backend.ErrNotFound)

	entries, err := lp.List(ctx, "db/")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "db/pw", entries[0].Path)
	assert.Equal(t, backend.ID("lp-3"), entries[0].Accessor)

	err = lp.Delete(ctx, "app/token")
	assert.ErrorIs(t, err, backend.ErrLocked)
	assert.NotContains(t, err.Error(), "lastpass.example", "raw stderr must not leak")

	require.NoError(t, lp.Close())
}

func TestLastPassFakeCLI_FactoryErrors(t *testing.T) {
	bkLPFakeCLI(t)
	f := bkLPFactory(t)

	_, err := f(context.Background(), backend.BackendConfig{Settings: map[string]interface{}{"vault": "x"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid settings")

	_, err = f(context.Background(), backend.BackendConfig{Settings: map[string]interface{}{"bin": filepath.Join(t.TempDir(), "lp")}})
	require.NoError(t, err)

	t.Setenv("PATH", t.TempDir())
	_, err = f(context.Background(), backend.BackendConfig{})
	assert.ErrorIs(t, err, backend.ErrUnavailable)
	_, err = lastpass.Open(lastpass.Options{})
	assert.ErrorIs(t, err, backend.ErrUnavailable)
}

func TestLastPass_ErrorMapping(t *testing.T) {
	runnerErr := errors.New("spawn failed")
	cases := []struct {
		name string
		resp kexec.MockResponse
		call func(*lastpass.LastPassBackend) error
		want error
		msg  string
	}{
		{"get runner error", kexec.MockResponse{Err: runnerErr}, bkLPGet, runnerErr, "runner error"},
		{"get generic failure", kexec.MockResponse{ExitCode: 3, Stderr: []byte("boom")}, bkLPGet, backend.ErrUnavailable, "get failed"},
		{"get bad json", kexec.MockResponse{Stdout: []byte("{nope")}, bkLPGet, backend.ErrUnavailable, "parse"},
		{"set runner error", kexec.MockResponse{Err: runnerErr}, bkLPSet, runnerErr, "runner error"},
		{"set generic failure", kexec.MockResponse{ExitCode: 1, Stderr: []byte("disk full")}, bkLPSet, backend.ErrUnavailable, "set failed"},
		{"delete runner error", kexec.MockResponse{Err: runnerErr}, bkLPDelete, runnerErr, "runner error"},
		{"delete auth", kexec.MockResponse{ExitCode: 1, Stderr: []byte("Session expired")}, bkLPDelete, backend.ErrLocked, "lpass login"},
		{"delete generic failure", kexec.MockResponse{ExitCode: 1, Stderr: []byte("boom")}, bkLPDelete, backend.ErrUnavailable, "delete failed"},
		{"list runner error", kexec.MockResponse{Err: runnerErr}, bkLPList, runnerErr, "runner error"},
		{"list auth", kexec.MockResponse{ExitCode: 1, Stderr: []byte("Invalid username or password")}, bkLPList, backend.ErrLocked, "lpass login"},
		{"list generic failure", kexec.MockResponse{ExitCode: 1, Stderr: []byte("boom")}, bkLPList, backend.ErrUnavailable, "list failed"},
		{"list bad json", kexec.MockResponse{Stdout: []byte("[{")}, bkLPList, nil, "decode list response"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := lastpass.Open(lastpass.Options{Bin: "/fake/lpass", Runner: &bkLPAnyRunner{resp: tc.resp}})
			require.NoError(t, err)
			err = tc.call(b)
			require.Error(t, err)
			if tc.want != nil {
				assert.ErrorIs(t, err, tc.want)
			}
			assert.Contains(t, err.Error(), tc.msg)
			assert.NotContains(t, err.Error(), "boom", "raw stderr must not leak")
		})
	}
}

func TestLastPass_GetHonoursCancelledContext(t *testing.T) {
	release := make(chan struct{})
	b, err := lastpass.Open(lastpass.Options{Bin: "/fake/lpass", Runner: &bkLPBlockingRunner{release: release}})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = b.Get(ctx, "app/token")
	close(release)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestLastPass_VersionedOperationsUnsupported(t *testing.T) {
	b, err := lastpass.Open(lastpass.Options{Bin: "/fake/lpass", Runner: &kexec.MockRunner{}})
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

func bkLPGet(b *lastpass.LastPassBackend) error {
	_, _, err := b.Get(context.Background(), "app/token")
	return err
}

func bkLPSet(b *lastpass.LastPassBackend) error {
	return b.Set(context.Background(), "app/token", []byte("v"), backend.Meta{})
}

func bkLPDelete(b *lastpass.LastPassBackend) error {
	return b.Delete(context.Background(), "app/token")
}

func bkLPList(b *lastpass.LastPassBackend) error {
	_, err := b.List(context.Background(), "")
	return err
}

type bkLPAnyRunner struct{ resp kexec.MockResponse }

func (r *bkLPAnyRunner) Run(_ context.Context, _ string, _ []string, _ []byte) ([]byte, []byte, int, error) {
	return r.resp.Stdout, r.resp.Stderr, r.resp.ExitCode, r.resp.Err
}

type bkLPBlockingRunner struct{ release chan struct{} }

func (r *bkLPBlockingRunner) Run(_ context.Context, _ string, _ []string, _ []byte) ([]byte, []byte, int, error) {
	<-r.release
	return nil, nil, 1, nil
}

func (r *bkLPAnyRunner) RunEnv(ctx context.Context, name string, args []string, stdin []byte, _ []string) ([]byte, []byte, int, error) {
	return r.Run(ctx, name, args, stdin)
}

func (r *bkLPBlockingRunner) RunEnv(ctx context.Context, name string, args []string, stdin []byte, _ []string) ([]byte, []byte, int, error) {
	return r.Run(ctx, name, args, stdin)
}
