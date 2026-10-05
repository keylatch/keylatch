package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/keylatch/keylatch/internal/vault"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

const migrateTestPath = "default/ai/openrouter/api_key"

type migrateVault struct {
	vaultDir string
	krPath   string
	cfg      config.Config
}

// newMigrateVault isolates every keylatch path and creates an age-identity
// keyring of the given algorithm that the CLI and the vault layer both open.
func newMigrateVault(t *testing.T, alg envelope.Algorithm) *migrateVault {
	t.Helper()
	testutil.ClearLLMSessionEnv(t)
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	v := &migrateVault{vaultDir: filepath.Join(root, "vault")}
	v.krPath = filepath.Join(v.vaultDir, "keyring", "keyring.json")
	identity := filepath.Join(root, "identity")
	for _, d := range []string{configDir, filepath.Dir(v.krPath)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("KEYLATCH_CONFIG_DIR", configDir)
	t.Setenv("KEYLATCH_CONFIG", filepath.Join(configDir, "config.json"))
	t.Setenv("KEYLATCH_VAULT_PATH", v.vaultDir)
	t.Setenv("KEYLATCH_DATA_DIR", v.vaultDir)
	t.Setenv("KEYLATCH_KEYRING_PATH", v.krPath)
	t.Setenv("KEYLATCH_KEYRING_DIR", filepath.Join(root, "keyring-dir"))
	t.Setenv("KEYLATCH_KEYRING_IDENTITY_PATH", identity)
	t.Setenv("KEYLATCH_AGE_IDENTITY", identity)
	t.Setenv("KEYLATCH_AUDIT_PATH", filepath.Join(configDir, "audit.log"))
	t.Setenv("KEYLATCH_AUDIT_SALT_PATH", filepath.Join(configDir, "audit-salt"))
	t.Setenv("KEYLATCH_BACKEND", "file")
	v.cfg = config.Config{Backend: "file", DataDir: v.vaultDir}
	dispatch.ClearCached()
	t.Cleanup(dispatch.ClearCached)

	id := make([]byte, 32)
	salt := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identity, id, 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := kek.AgeIdentityKEKFromPath(identity, salt)
	if err != nil {
		t.Fatal(err)
	}
	var lease uint64
	if alg == envelope.AES256GCM {
		lease = 1024
	}
	if err := keyring.NewWithSalt(v.krPath, k, alg, lease, salt); err != nil {
		t.Fatal(err)
	}
	return v
}

func (v *migrateVault) rotate(t *testing.T, value string) {
	t.Helper()
	if _, err := vault.RotateValue(audit.WithEmitter(context.Background(), discardAudit{}), migrateTestPath, []byte(value), vmeta.Meta{}, v.cfg, os.Getenv); err != nil {
		t.Fatalf("RotateValue: %v", err)
	}
}

func (v *migrateVault) readVersion(t *testing.T, version int) string {
	t.Helper()
	dispatch.ClearCached()
	got, _, err := vault.GetVersion(context.Background(), migrateTestPath, version, v.cfg, os.Getenv)
	if err != nil {
		t.Fatalf("GetVersion v%d: %v", version, err)
	}
	return string(got)
}

func (v *migrateVault) keyringAlgorithm(t *testing.T) envelope.Algorithm {
	t.Helper()
	data, err := os.ReadFile(v.krPath)
	if err != nil {
		t.Fatal(err)
	}
	var kf keyring.KeyringFile
	if err := json.Unmarshal(data, &kf); err != nil {
		t.Fatal(err)
	}
	return kf.Algorithm
}

func runMigrate(t *testing.T, to envelope.Algorithm) (string, error) {
	t.Helper()
	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"migrate", "cipher", "--to", string(to)})
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

func TestMigrateCipherReencryptsEveryStoredVersion(t *testing.T) {
	v := newMigrateVault(t, envelope.XChaCha20Poly1305)
	values := []string{"first-value", "second-value", "third-value"}
	for _, val := range values {
		v.rotate(t, val)
	}

	for _, to := range []envelope.Algorithm{envelope.AES256GCM, envelope.XChaCha20Poly1305} {
		out, err := runMigrate(t, to)
		if err != nil {
			t.Fatalf("migrate to %s: %v\n%s", to, err, out)
		}
		want := fmt.Sprintf("migration complete: %d value(s) re-encrypted under %q", len(values), to)
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Fatalf("output %q does not contain %q", out, want)
		}
		if got := v.keyringAlgorithm(t); got != to {
			t.Fatalf("keyring algorithm = %s, want %s", got, to)
		}
		for i, val := range values {
			if got := v.readVersion(t, i+1); got != val {
				t.Fatalf("after migrating to %s, v%d = %q, want %q", to, i+1, got, val)
			}
		}
		m, err := vault.GetMeta(context.Background(), migrateTestPath, v.cfg, os.Getenv)
		if err != nil {
			t.Fatal(err)
		}
		for _, vm := range m.Versions {
			if vm.AAD.Algorithm != string(to) {
				t.Fatalf("metadata for v%d records %q, want %q", vm.Version, vm.AAD.Algorithm, to)
			}
		}
		if bytes.Contains([]byte(out), []byte(values[0])) {
			t.Fatal("migration output contains a secret value")
		}
	}
}

func TestMigrateCipherUnreadableVersionChangesNothing(t *testing.T) {
	v := newMigrateVault(t, envelope.XChaCha20Poly1305)
	v.rotate(t, "first-value")
	v.rotate(t, "second-value")

	corrupt := valuePath(v.vaultDir, migrateTestPath, 2)
	ct, err := os.ReadFile(corrupt)
	if err != nil {
		t.Fatal(err)
	}
	ct[0] ^= 0xff
	if err := os.WriteFile(corrupt, ct, 0o600); err != nil {
		t.Fatal(err)
	}
	keyringBefore, err := os.ReadFile(v.krPath)
	if err != nil {
		t.Fatal(err)
	}

	out, err := runMigrate(t, envelope.AES256GCM)
	if err == nil {
		t.Fatalf("migration of an unreadable version succeeded:\n%s", out)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("nothing was changed")) {
		t.Fatalf("error %q does not say the vault is unchanged", err)
	}
	keyringAfter, err := os.ReadFile(v.krPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keyringBefore, keyringAfter) {
		t.Fatal("keyring changed although the migration aborted")
	}
	if got := v.readVersion(t, 1); got != "first-value" {
		t.Fatalf("v1 = %q after aborted migration", got)
	}
}

func TestMigrateCipherRollbackRestoresVersionFiles(t *testing.T) {
	v := newMigrateVault(t, envelope.XChaCha20Poly1305)
	v.rotate(t, "first-value")
	ctPath := valuePath(v.vaultDir, migrateTestPath, 1)

	orig := map[string][]byte{}
	for _, p := range []string{ctPath, ctPath + ".nonce", ctPath + versionBindingSuffix} {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		orig[p] = data
	}
	backup, err := snapshotVersion(storedVersion{ctPath: ctPath})
	if err != nil {
		t.Fatal(err)
	}
	for p := range orig {
		if err := os.WriteFile(p, []byte("rewritten"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cmd := NewRootCommand()
	var errOut bytes.Buffer
	cmd.SetErr(&errOut)
	sentinel := fmt.Errorf("write failed")
	if got := rollback(cmd, nil, context.Background(), []migrateBackup{backup}, nil, sentinel); got != sentinel {
		t.Fatalf("rollback returned %v, want the original error", got)
	}
	for p, want := range orig {
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s not restored", filepath.Base(p))
		}
	}
	if got := v.readVersion(t, 1); got != "first-value" {
		t.Fatalf("v1 = %q after rollback", got)
	}
}

// discardAudit accepts every event, so seeding versions works whether or not
// the vault requires an audit emitter.
type discardAudit struct{}

func (discardAudit) Emit(context.Context, audit.Event) error { return nil }
