package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend/credref"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/testutil"
)

func runBackendLogin(t *testing.T, args ...string) error {
	t.Helper()
	cmd := newBackendLoginCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(args)
	return cmd.ExecuteContext(context.Background())
}

func credentialDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(paths.ConfigDir(llmcontext.DefaultLookup), "backend-credentials")
}

// A credential is only taken from a person at a terminal; neither a pipe nor
// an agent session stores one, and nothing is written when refused.
func TestBackendLoginNeedsPresence(t *testing.T) {
	testutil.SetupHermeticConfig(t)
	testutil.SetupTestKeyring(t)

	t.Run("no terminal", func(t *testing.T) {
		testutil.ClearLLMSessionEnv(t)
		withInteractiveStdin(t, false)
		err := runBackendLogin(t, "vault")
		assertSecurityBlock(t, err)
		if !strings.Contains(err.Error(), "interactive terminal") {
			t.Errorf("error = %q", err)
		}
	})

	t.Run("agent session", func(t *testing.T) {
		testutil.ClearLLMSessionEnv(t)
		t.Setenv("CLAUDECODE", "1")
		withInteractiveStdin(t, true)
		assertSecurityBlock(t, runBackendLogin(t, "vault"))
	})

	if _, err := os.Stat(credentialDir(t)); !os.IsNotExist(err) {
		t.Fatalf("a refused login wrote a credential: %v", err)
	}
	if cfg := loadCLIConfig(newBackendLoginCmd()); len(cfg.Backends) != 0 {
		t.Fatalf("a refused login changed the config: %v", cfg.Backends)
	}
}

func TestBackendLoginStoresWrappedCredential(t *testing.T) {
	testutil.SetupHermeticConfig(t)
	testutil.SetupTestKeyring(t)
	testutil.ClearLLMSessionEnv(t)
	withInteractiveStdin(t, true)

	answers := []string{"s.vault-token-value", "", ""} // token, role_id, secret_id
	prev := promptHiddenFn
	promptHiddenFn = func() ([]byte, error) {
		v := answers[0]
		answers = answers[1:]
		return []byte(v), nil
	}
	t.Cleanup(func() { promptHiddenFn = prev })

	if err := runBackendLogin(t, "vault", "--ref", "prod-vault"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(credref.Path(llmcontext.DefaultLookup, "prod-vault"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("s.vault-token-value")) {
		t.Fatal("credential stored in the clear")
	}
	cfg, err := config.Load(paths.Config(llmcontext.DefaultLookup))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Backends["vault"]; got.CredentialRef != "prod-vault" || got.AllowEnvCredentials {
		t.Fatalf("config backends.vault = %+v", got)
	}

	if err := runBackendLogin(t, "nope"); err == nil {
		t.Fatal("unknown backend accepted")
	}
}
