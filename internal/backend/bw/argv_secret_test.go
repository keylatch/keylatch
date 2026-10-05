package bw_test

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/bw"
	"github.com/stretchr/testify/require"
)

const argvTripwireSecret = "argv-tripwire-7f3a9c"

// fakeBWScript records every invocation's argv and stdin in the script's
// directory. `get item` answers from item.json when it exists.
const fakeBWScript = `#!/bin/sh
d=$(dirname "$0")
printf '%s\n' "$*" >>"$d/argv"
case "$1 $2" in
"get item")
  if [ -f "$d/item.json" ]; then cat "$d/item.json"; else echo "Not found." >&2; exit 1; fi ;;
"create item"|"edit item")
  cat >>"$d/stdin"; echo '{"id":"item1"}' ;;
esac
`

func writeFakeBW(t *testing.T, itemJSON string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell stub")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bw")
	require.NoError(t, os.WriteFile(bin, []byte(fakeBWScript), 0o700))
	if itemJSON != "" {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "item.json"), []byte(itemJSON), 0o600))
	}
	return bin
}

func TestSetKeepsSecretOffArgv(t *testing.T) {
	cases := map[string]string{
		"create": "",
		"edit":   `{"id":"item1","name":"openrouter","type":1,"fields":[{"name":"api_key","value":"old","type":1}]}`,
	}
	for name, existing := range cases {
		t.Run(name, func(t *testing.T) {
			bin := writeFakeBW(t, existing)
			env := func(k string) string {
				if k == "BW_SESSION" {
					return "session-token-value"
				}
				return ""
			}
			b, err := bw.Open(bw.Options{Bin: bin, Env: env})
			require.NoError(t, err)

			require.NoError(t, b.Set(context.Background(), "default/openrouter/api_key", []byte(argvTripwireSecret), backend.Meta{}))

			dir := filepath.Dir(bin)
			argv, err := os.ReadFile(filepath.Join(dir, "argv"))
			require.NoError(t, err)
			require.Contains(t, string(argv), name+" item")
			require.NotContains(t, string(argv), argvTripwireSecret)
			require.NotContains(t, string(argv), "session-token-value")
			for _, line := range strings.Split(strings.TrimSpace(string(argv)), "\n") {
				for _, arg := range strings.Fields(line) {
					if decoded, err := base64.StdEncoding.DecodeString(arg); err == nil {
						require.NotContains(t, string(decoded), argvTripwireSecret, "encoded secret on argv")
					}
				}
			}

			stdin, err := os.ReadFile(filepath.Join(dir, "stdin"))
			require.NoError(t, err)
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(stdin)))
			require.NoError(t, err)
			require.Contains(t, string(decoded), argvTripwireSecret, "the item JSON must arrive on stdin")
		})
	}
}
