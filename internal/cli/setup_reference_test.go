package cli

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/store"
	"github.com/keylatch/keylatch/internal/testutil"
)

type referenceRunner struct{}

func (referenceRunner) Run(context.Context, string, []string, []byte) ([]byte, []byte, int, error) {
	return []byte("resolved-value"), nil, 0, nil
}

func (r referenceRunner) RunEnv(ctx context.Context, bin string, args []string, stdin []byte, _ []string) ([]byte, []byte, int, error) {
	return r.Run(ctx, bin, args, stdin)
}

// On a fresh install the config directory does not exist yet; reference
// mode never bootstraps, so saving the URI must create it.
func TestSetupReferenceOnFreshInstall(t *testing.T) {
	testutil.ClearLLMSessionEnv(t)
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "keylatch")
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("KEYLATCH_CONFIG_DIR", cfgDir)
	t.Setenv("KEYLATCH_CONFIG", "")

	oldResolver := storeNewResolver
	t.Cleanup(func() { storeNewResolver = oldResolver })
	storeNewResolver = func() *store.Resolver {
		return store.NewResolver(referenceRunner{}).WithBinOverride("op", "/fake/bin/op")
	}

	uri := "op://Private/Anthropic/api_key"
	oldScanner := stdinScannerFn
	t.Cleanup(func() {
		stdinScannerFn = oldScanner
		scannerOnce = &sync.Once{}
		sharedScanner = nil
	})
	scannerOnce = &sync.Once{}
	sharedScanner = nil
	stdinScannerFn = func() *bufio.Scanner {
		return bufio.NewScanner(strings.NewReader("reference\n" + uri + "\n"))
	}

	root := NewRootCommand()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs([]string{"setup"})
	if err := root.Execute(); err != nil {
		t.Fatalf("setup: %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "URI saved.") {
		t.Fatalf("setup did not save the URI:\n%s\n%s", out.String(), errOut.String())
	}

	cfg, err := config.Load(filepath.Join(cfgDir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultProviderRef != uri {
		t.Fatalf("DefaultProviderRef = %q, want %q", cfg.DefaultProviderRef, uri)
	}
	if _, err := os.Stat(filepath.Join(cfgDir, "keyring")); !os.IsNotExist(err) {
		t.Fatalf("reference mode created a local keyring: %v", err)
	}
}
