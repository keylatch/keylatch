package op_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/op"
	"github.com/stretchr/testify/require"
)

const argvTripwireSecret = "argv-tripwire-7f3a9c"

// fakeOpScript records every invocation's argv and stdin in the script's
// directory. `item get` answers from item.json when it exists.
const fakeOpScript = `#!/bin/sh
d=$(dirname "$0")
printf '%s\n' "$*" >>"$d/argv"
case "$1 $2" in
"item get")
  if [ -f "$d/item.json" ]; then cat "$d/item.json"; else echo "\"x\" isn't an item in the \"Keylatch\" vault" >&2; exit 1; fi ;;
"item create"|"item edit")
  cat >"$d/stdin"; echo '{"id":"item1"}' ;;
esac
`

const existingOpItem = `{"id":"abc123","title":"openrouter","category":"API_CREDENTIAL",
"sections":[{"id":"s1","label":"extra"}],
"fields":[{"id":"f1","label":"api_key","type":"CONCEALED","value":"old"},
{"id":"f2","label":"base_url","type":"STRING","value":"https://openrouter.ai/api/v1","section":{"id":"s1"}}]}`

func writeFakeOp(t *testing.T, itemJSON string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell stub")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "op")
	require.NoError(t, os.WriteFile(bin, []byte(fakeOpScript), 0o700))
	if itemJSON != "" {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "item.json"), []byte(itemJSON), 0o600))
	}
	return bin
}

type templateItem struct {
	Sections []map[string]any `json:"sections"`
	Fields   []struct {
		Label string `json:"label"`
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"fields"`
}

func runOpSet(t *testing.T, existing string) (argv string, tmpl templateItem) {
	t.Helper()
	bin := writeFakeOp(t, existing)
	b, err := op.Open(op.Options{Bin: bin, Vault: "Keylatch"})
	require.NoError(t, err)
	require.NoError(t, b.Set(context.Background(), "default/openrouter/api_key", []byte(argvTripwireSecret), backend.Meta{}))

	dir := filepath.Dir(bin)
	rawArgv, err := os.ReadFile(filepath.Join(dir, "argv"))
	require.NoError(t, err)
	stdin, err := os.ReadFile(filepath.Join(dir, "stdin"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(stdin, &tmpl))
	return string(rawArgv), tmpl
}

func TestSetCreateKeepsSecretOffArgv(t *testing.T) {
	argv, tmpl := runOpSet(t, "")
	require.Contains(t, argv, "item create -")
	require.NotContains(t, argv, argvTripwireSecret)
	require.Len(t, tmpl.Fields, 1)
	require.Equal(t, "api_key", tmpl.Fields[0].Label)
	require.Equal(t, "CONCEALED", tmpl.Fields[0].Type)
	require.Equal(t, argvTripwireSecret, tmpl.Fields[0].Value)
}

func TestSetEditKeepsSecretOffArgvAndPreservesItem(t *testing.T) {
	argv, tmpl := runOpSet(t, existingOpItem)
	require.Contains(t, argv, "item edit openrouter")
	require.NotContains(t, argv, argvTripwireSecret)
	require.Len(t, tmpl.Sections, 1, "unmodelled item properties must survive the edit")
	require.Len(t, tmpl.Fields, 2)
	require.Equal(t, argvTripwireSecret, tmpl.Fields[0].Value)
	require.Equal(t, "https://openrouter.ai/api/v1", tmpl.Fields[1].Value)
}
