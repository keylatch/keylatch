package cli

import (
	"bufio"
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/spf13/cobra"
)

// ccEnv isolates config, vault, keyring, HOME and LLM-session signals for one
// test and points the dispatched store at a fresh file backend. It returns the
// config directory (local provider templates live beneath it).
func ccEnv(t *testing.T) string {
	t.Helper()
	testutil.ClearLLMSessionEnv(t)
	cfgDir := testutil.SetupHermeticConfig(t)
	t.Setenv("KEYLATCH_DATA_DIR", t.TempDir())
	t.Setenv("KEYLATCH_VAULT_PATH", "")
	t.Setenv("KEYLATCH_BACKEND", "file")
	t.Setenv("KEYLATCH_GATEWAY_PID", filepath.Join(t.TempDir(), "gateway.pid"))
	t.Setenv("KEYLATCH_UI_ADDR", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	testutil.SetupTestKeyring(t)
	dispatch.ClearCached()
	t.Cleanup(dispatch.ClearCached)
	ccNonTTYStdin(t, "")
	return cfgDir
}

// ccNonTTYStdin replaces os.Stdin with a pipe carrying input so that TTY
// detection is deterministic and readLine never blocks on a terminal.
func ccNonTTYStdin(t *testing.T, input string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if _, err := w.WriteString(input); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	_ = w.Close()
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = old
		_ = r.Close()
	})
}

// ccScriptLines feeds lines to readLine() for the duration of the test.
func ccScriptLines(t *testing.T, lines ...string) {
	t.Helper()
	oldFn := stdinScannerFn
	scannerOnce = &sync.Once{}
	sharedScanner = nil
	stdinScannerFn = func() *bufio.Scanner {
		return bufio.NewScanner(strings.NewReader(strings.Join(lines, "\n") + "\n"))
	}
	t.Cleanup(func() {
		stdinScannerFn = oldFn
		scannerOnce = &sync.Once{}
		sharedScanner = nil
	})
}

// ccTemplate is the YAML for a local provider template whose connection test
// and action catalog target endpoint (an httptest server).
func ccTemplate(name, endpoint string) string {
	return `provider: ` + name + `
display_name: CC ` + name + `
category: ai
description: "local test provider"
docs_url: https://docs.example.invalid/` + name + `
secret_fields:
  - name: api_key
    label: API Key
    required: true
    sensitive: true
    env_var: CC_` + strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + `_KEY
auth_flow: api_key
auth_placement:
  in: header
  name: Authorization
  scheme: Bearer
storage_path_tpl: "{{.Namespace}}/ai/` + name + `/{{.Account}}"
trust_level: 3
runtime_support:
  preferred: gateway_typed
  supported:
    - gateway_typed
capabilities:
  - name: models.list
    description: List models
actions:
  list-models:
    method: GET
    path: /v1/models
test_strategy:
  kind: http_get
  endpoint: ` + endpoint + `/v1/models
  expect:
    status_code: 200
    markers:
      - data
`
}

// ccWriteTemplate installs a local provider template under cfgDir.
func ccWriteTemplate(t *testing.T, cfgDir, name, yaml string) {
	t.Helper()
	dir := filepath.Join(cfgDir, "templates", "providers")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir templates: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}
}

// ccInitRegistry loads the embedded providers plus the local templates that
// ccWriteTemplate wrote; the binary itself loads only embedded providers.
func ccInitRegistry(ctx context.Context) error {
	if err := registry.InitFromConfig(ctx, llmcontext.DefaultLookup); err != nil {
		return err
	}
	local := &registry.FSLoader{
		Dir:  filepath.Join(paths.ConfigDir(llmcontext.DefaultLookup), "templates", "providers"),
		Tier: registry.TierLocal,
	}
	loaded, err := local.LoadAll(ctx)
	if err != nil {
		return err
	}
	for _, lt := range loaded {
		if err := registry.Register(lt.Template); err != nil {
			return err
		}
	}
	return nil
}

// ccRun executes the root command with args and stdin, returning captured
// stdout, stderr and the command error.
func ccRun(t *testing.T, stdin string, args ...string) (string, string, error) {
	t.Helper()
	root := NewRootCommand()
	root.PersistentPreRunE = func(c *cobra.Command, _ []string) error {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
		return ccInitRegistry(c.Context())
	}
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return out.String(), errb.String(), err
}

// ccSecret builds a credential-shaped value at runtime without embedding a
// recognisable token literal in the source.
func ccSecret(tag string) string {
	return "cc" + tag + strings.Repeat("Zq7", 10)
}
