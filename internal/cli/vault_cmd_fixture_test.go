package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/keylatch/keylatch/internal/vault"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

// caFixture is a fully isolated keylatch installation: config dir, vault dir,
// an age identity and a keyring that both the file backend and the keyring
// commands resolve to.
type caFixture struct {
	root      string
	configDir string
	vaultDir  string
	krPath    string
	identity  string
	salt      []byte
	cfg       config.Config
}

// caNewEnv isolates every keylatch path and clears LLM session signals, but
// does not create a keyring.
func caNewEnv(t *testing.T) *caFixture {
	t.Helper()
	testutil.ClearLLMSessionEnv(t)
	root := t.TempDir()
	f := &caFixture{
		root:      root,
		configDir: filepath.Join(root, "config"),
		vaultDir:  filepath.Join(root, "vault"),
		identity:  filepath.Join(root, "identity"),
	}
	f.krPath = filepath.Join(f.vaultDir, "keyring", "keyring.json")
	if err := os.MkdirAll(f.configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYLATCH_CONFIG_DIR", f.configDir)
	t.Setenv("KEYLATCH_CONFIG", filepath.Join(f.configDir, "config.json"))
	t.Setenv("KEYLATCH_VAULT_PATH", f.vaultDir)
	t.Setenv("KEYLATCH_DATA_DIR", f.vaultDir)
	t.Setenv("KEYLATCH_KEYRING_PATH", f.krPath)
	t.Setenv("KEYLATCH_KEYRING_DIR", filepath.Join(root, "keyring-dir"))
	t.Setenv("KEYLATCH_KEYRING_IDENTITY_PATH", f.identity)
	t.Setenv("KEYLATCH_AGE_IDENTITY", f.identity)
	t.Setenv("KEYLATCH_AUDIT_PATH", filepath.Join(f.configDir, "audit.log"))
	t.Setenv("KEYLATCH_AUDIT_SALT_PATH", filepath.Join(f.configDir, "audit-salt"))
	t.Setenv("KEYLATCH_BACKEND", "file")
	t.Setenv("KEYLATCH_GATEWAY_DIR", filepath.Join(root, "gateway"))
	t.Setenv("KEYLATCH_GATEWAY_ADDR", "")
	t.Setenv("KEYLATCH_PROXY_ADDR", "")
	t.Setenv("KEYLATCH_MODE", "")
	t.Setenv("KEYLATCH_EXPERIMENTAL", "")
	f.cfg = config.Config{Backend: "file", DataDir: f.vaultDir}
	dispatch.ClearCached()
	t.Cleanup(dispatch.ClearCached)
	return f
}

// caWriteIdentity writes a random 0600 age identity file.
func caWriteIdentity(t *testing.T, path string) {
	t.Helper()
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, id, 0o600); err != nil {
		t.Fatal(err)
	}
}

// caNewVault builds an isolated environment with an age-env keyring of the
// given algorithm that every code path (backend factory, keyring commands,
// audit logger) can open without user interaction.
func caNewVault(t *testing.T, alg envelope.Algorithm) *caFixture {
	t.Helper()
	f := caNewEnv(t)
	caWriteIdentity(t, f.identity)
	f.salt = make([]byte, 32)
	if _, err := rand.Read(f.salt); err != nil {
		t.Fatal(err)
	}
	k, err := kek.AgeIdentityKEKFromPath(f.identity, f.salt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(f.krPath), 0o700); err != nil {
		t.Fatal(err)
	}
	var lease uint64
	if alg == envelope.AES256GCM {
		lease = 1024
	}
	if err := keyring.NewWithSalt(f.krPath, k, alg, lease, f.salt); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *caFixture) env(k string) string { return os.Getenv(k) }

// rotate writes a new version of path through the vault layer.
func (f *caFixture) rotate(t *testing.T, path string, value []byte) int {
	t.Helper()
	v, err := vault.RotateValue(audit.WithEmitter(context.Background(), discardAudit{}), path, value, vmeta.Meta{}, f.cfg, f.env)
	if err != nil {
		t.Fatalf("RotateValue %s: %v", path, err)
	}
	return v
}

func (f *caFixture) meta(t *testing.T, path string) vmeta.Meta {
	t.Helper()
	m, err := vault.GetMeta(context.Background(), path, f.cfg, f.env)
	if err != nil {
		t.Fatalf("GetMeta %s: %v", path, err)
	}
	return m
}

// caRun executes the root command with args and stdin, returning stdout,
// stderr and the error returned by Execute.
func caRun(t *testing.T, stdin io.Reader, args ...string) (string, string, error) {
	t.Helper()
	root := NewRootCommand()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	if stdin != nil {
		root.SetIn(stdin)
	}
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return out.String(), errOut.String(), err
}

// caRunAudited is caRun with an audit emitter in the command context, for
// commands that leave the emitter to their caller.
func caRunAudited(t *testing.T, stdin io.Reader, args ...string) (string, string, error) {
	t.Helper()
	root := NewRootCommand()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	if stdin != nil {
		root.SetIn(stdin)
	}
	root.SetArgs(args)
	err := root.ExecuteContext(audit.WithEmitter(context.Background(), discardAudit{}))
	return out.String(), errOut.String(), err
}

// caExitCode is the process exit code main would use for err.
func caExitCode(err error) int {
	return ReportError(NewRootCommand(), nil, err, io.Discard)
}

// caStdinFile returns an *os.File (not a terminal) whose content is data.
func caStdinFile(t *testing.T, data string) *os.File {
	t.Helper()
	p := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	fh, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fh.Close() })
	return fh
}

// caSwapStdin replaces os.Stdin with a file containing data for the test.
func caSwapStdin(t *testing.T, data string) {
	t.Helper()
	fh := caStdinFile(t, data)
	orig := os.Stdin
	os.Stdin = fh
	t.Cleanup(func() { os.Stdin = orig })
}

// caSetLLMSession marks the process as running inside an LLM agent session.
func caSetLLMSession(t *testing.T) {
	t.Helper()
	sig := llmcontext.Signals[0]
	t.Setenv(sig.EnvKey, "1")
	if !llmcontext.IsLLMSession(os.Getenv) {
		t.Fatalf("setting %s did not produce an LLM session", sig.EnvKey)
	}
}
