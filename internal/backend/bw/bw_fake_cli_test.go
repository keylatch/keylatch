package bw_test

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
	"github.com/keylatch/keylatch/internal/backend/bw"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// bkBWFakeCLI installs a fake `bw` on an otherwise empty PATH. The script
// records argv and whether BW_SESSION was visible, then prints an item.
func bkBWFakeCLI(t *testing.T) (dir, argvLog, envLog string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake CLI requires a POSIX shell")
	}
	dir = t.TempDir()
	argvLog = filepath.Join(dir, "argv.log")
	envLog = filepath.Join(dir, "env.log")
	script := `#!/bin/sh
printf '%s\n' "$@" >> "` + argvLog + `"
printf '%s\n' "${BW_SESSION:-<unset>}" >> "` + envLog + `"
case "$1" in
  get) printf '{"id":"it-9","name":"%s","fields":[{"name":"api_key","value":"from-fake-cli","type":1}]}' "$3" ;;
  *) echo "unexpected" >&2; exit 2 ;;
esac
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bw"), []byte(script), 0o700))
	t.Setenv("PATH", dir)
	return dir, argvLog, envLog
}

func TestBWFactory_FakeCLIOnPath_SessionViaEnvOnly(t *testing.T) {
	_, argvLog, envLog := bkBWFakeCLI(t)
	session := strings.Repeat("s", 8) + "-sess"
	t.Setenv("BW_SESSION", session)

	factory, ok := backend.Default.Get("bw")
	require.True(t, ok)

	cases := map[string]interface{}{
		"plain func":         func(k string) string { return os.Getenv(k) },
		"llmcontext.Lookup":  llmcontext.Lookup(os.Getenv),
		"unrecognised value": 42,
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			_ = os.Remove(argvLog)
			b, err := factory(context.Background(), backend.BackendConfig{
				Name:     "bw",
				Settings: map[string]interface{}{"server": "https://vw.example.test", "env": env},
			})
			require.NoError(t, err)
			assert.Equal(t, "bw:https://vw.example.test", b.ID())

			val, _, err := b.Get(context.Background(), "default/svc/api_key")
			require.NoError(t, err)
			assert.Equal(t, "from-fake-cli", string(val))

			argv, err := os.ReadFile(argvLog)
			require.NoError(t, err)
			assert.Equal(t, "get\nitem\nsvc\n", string(argv))
			assert.NotContains(t, string(argv), session)
			assert.NotContains(t, string(argv), "--session")
		})
	}

	envSeen, err := os.ReadFile(envLog)
	require.NoError(t, err)
	assert.Contains(t, string(envSeen), session, "session reaches the CLI through the inherited environment")
}

func TestBWFactory_RejectsPlainHTTPServer(t *testing.T) {
	bkBWFakeCLI(t)
	factory, ok := backend.Default.Get("bw")
	require.True(t, ok)
	_, err := factory(context.Background(), backend.BackendConfig{
		Name:     "bw",
		Settings: map[string]interface{}{"server": "http://vw.example.test"},
	})
	var invalid bw.ErrInvalidServer
	require.True(t, errors.As(err, &invalid), "err=%v", err)
	assert.Equal(t, "http://vw.example.test", invalid.URL)
}

func TestBWOpen_NoBinaryOnPath_Unavailable(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	b, err := bw.Open(bw.Options{})
	require.Error(t, err)
	assert.Nil(t, b)
	assert.ErrorIs(t, err, backend.ErrUnavailable)
	assert.Contains(t, err.Error(), "Bitwarden CLI not found")
}

func TestBWOpen_DefaultsUseProcessEnvAndRealRunner(t *testing.T) {
	dir, argvLog, _ := bkBWFakeCLI(t)
	b, err := bw.Open(bw.Options{Bin: filepath.Join(dir, "bw")})
	require.NoError(t, err)

	// The fake exits 2 for anything but `get`; the raw stderr must not leak.
	_, err = b.List(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bw exited 2")
	assert.NotContains(t, err.Error(), "unexpected")

	argv, err := os.ReadFile(argvLog)
	require.NoError(t, err)
	assert.Equal(t, "list\nitems\n--search=keylatch\n", string(argv))
}
