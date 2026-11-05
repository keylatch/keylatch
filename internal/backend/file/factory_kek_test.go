//go:build !fips

package file_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
)

func bkFileFactory(t *testing.T) backend.Factory {
	t.Helper()
	f, ok := backend.Default.Get("file")
	if !ok {
		t.Fatal("file backend not registered")
	}
	return f
}

func bkWriteKeyringFile(t *testing.T, path string, kf keyring.KeyringFile) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(kf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// bkAgeKeyring writes an age-env keyring whose DEK is wrapped under the KEK
// derived from identityPath, exactly as the factory will re-derive it.
func bkAgeKeyring(t *testing.T, krPath, identityPath string) {
	t.Helper()
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 11)
	}
	k, err := kek.AgeIdentityKEKFromPath(identityPath, salt)
	if err != nil {
		t.Fatalf("AgeIdentityKEKFromPath: %v", err)
	}
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(200 - i)
	}
	wrapped, err := k.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	bkWriteKeyringFile(t, krPath, keyring.KeyringFile{
		SchemaVersion: keyring.SchemaVersion,
		Algorithm:     envelope.XChaCha20Poly1305,
		ActiveTerm:    1,
		KEKType:       "age-env",
		Salt:          salt,
		Terms: []keyring.TermRecord{{
			Term:       1,
			Status:     keyring.TermActive,
			WrappedDEK: wrapped,
			CreatedAt:  time.Now().UTC().Format(time.RFC3339),
			KEKType:    "age-env",
		}},
	})
}

func bkWriteIdentity(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFileFactory_AgeEnvKeyring_RoundTrip(t *testing.T) {
	base := t.TempDir()
	idPath := filepath.Join(base, "id", "identity")
	bkWriteIdentity(t, idPath, "test-identity-"+strings.Repeat("q", 40))
	krPath := filepath.Join(base, "kr", "keyring.json")
	bkAgeKeyring(t, krPath, idPath)
	t.Setenv("KEYLATCH_AGE_IDENTITY", idPath)

	dataDir := filepath.Join(base, "vault")
	b, err := bkFileFactory(t)(context.Background(), backend.BackendConfig{
		Name:     "file",
		Settings: map[string]interface{}{"data_dir": dataDir, "keyring_path": krPath},
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	ctx := context.Background()
	if err := b.Set(ctx, "default/app/token", []byte("plain-value"), backend.Meta{}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, _, err := b.Get(ctx, "default/app/token")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "plain-value" {
		t.Fatalf("Get = %q", got)
	}
	enc, err := os.ReadFile(filepath.Join(dataDir, "default", "app", "token", "value.enc"))
	if err != nil {
		t.Fatalf("read value.enc: %v", err)
	}
	if strings.Contains(string(enc), "plain-value") {
		t.Fatal("value.enc contains plaintext")
	}
}

func TestFileFactory_AgeEnvFallsBackToKeyringIdentityPath(t *testing.T) {
	cfgDir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", cfgDir)
	t.Setenv("KEYLATCH_AGE_IDENTITY", "")
	t.Setenv("KEYLATCH_KEYRING_PATH", "")
	t.Setenv("KEYLATCH_KEYRING_IDENTITY_PATH", "")
	t.Setenv("KEYLATCH_KEYRING_DIR", "")

	idPath := filepath.Join(cfgDir, "keyring", "identity")
	bkWriteIdentity(t, idPath, "fallback-identity-"+strings.Repeat("z", 40))
	krPath := filepath.Join(cfgDir, "keyring", "keyring.json")
	bkAgeKeyring(t, krPath, idPath)

	b, err := bkFileFactory(t)(context.Background(), backend.BackendConfig{
		Name:     "file",
		Settings: map[string]interface{}{"data_dir": filepath.Join(cfgDir, "vault")},
	})
	if err != nil {
		t.Fatalf("factory with default keyring and identity paths: %v", err)
	}
	if b.Name() != "file" {
		t.Fatalf("Name() = %q", b.Name())
	}
}

func TestFileFactory_WrongAgeIdentity_FailsClosedWithoutLeakingIdentity(t *testing.T) {
	base := t.TempDir()
	goodID := filepath.Join(base, "good")
	bkWriteIdentity(t, goodID, "good-identity-"+strings.Repeat("a", 40))
	krPath := filepath.Join(base, "keyring.json")
	bkAgeKeyring(t, krPath, goodID)

	wrongContent := "wrong-identity-" + strings.Repeat("b", 40)
	wrongID := filepath.Join(base, "wrong")
	bkWriteIdentity(t, wrongID, wrongContent)
	t.Setenv("KEYLATCH_AGE_IDENTITY", wrongID)

	_, err := bkFileFactory(t)(context.Background(), backend.BackendConfig{
		Name:     "file",
		Settings: map[string]interface{}{"data_dir": filepath.Join(base, "vault"), "keyring_path": krPath},
	})
	if !errors.Is(err, backend.ErrBootstrapRequired) {
		t.Fatalf("got %v, want ErrBootstrapRequired", err)
	}
	if !strings.Contains(err.Error(), "cannot open keyring") {
		t.Errorf("error should name the keyring open failure: %v", err)
	}
	if strings.Contains(err.Error(), wrongContent) {
		t.Fatal("identity content leaked into error")
	}
}

func TestFileFactory_AgeIdentityWithLooseMode_Rejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not enforced on windows")
	}
	base := t.TempDir()
	idPath := filepath.Join(base, "identity")
	bkWriteIdentity(t, idPath, "identity-"+strings.Repeat("c", 40))
	krPath := filepath.Join(base, "keyring.json")
	bkAgeKeyring(t, krPath, idPath)
	if err := os.Chmod(idPath, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYLATCH_AGE_IDENTITY", idPath)

	_, err := bkFileFactory(t)(context.Background(), backend.BackendConfig{
		Name:     "file",
		Settings: map[string]interface{}{"data_dir": filepath.Join(base, "vault"), "keyring_path": krPath},
	})
	if !errors.Is(err, backend.ErrBootstrapRequired) {
		t.Fatalf("got %v, want ErrBootstrapRequired", err)
	}
	if !strings.Contains(err.Error(), "cannot load keyring KEK") || !strings.Contains(err.Error(), "0644") {
		t.Errorf("error should explain the identity mode problem: %v", err)
	}
}

func TestFileFactory_KEKTypeSelection_FailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		kf      keyring.KeyringFile
		wantSub string
	}{
		{"passphrase needs interactive input", keyring.KeyringFile{SchemaVersion: keyring.SchemaVersion, KEKType: "passphrase"}, "passphrase KEK requires interactive input"},
		{"unknown kek type", keyring.KeyringFile{SchemaVersion: keyring.SchemaVersion, KEKType: "carrier-pigeon"}, `unsupported KEK type "carrier-pigeon"`},
		{"empty kek type", keyring.KeyringFile{SchemaVersion: keyring.SchemaVersion}, `unsupported KEK type ""`},
		{"roots keyring uses first root type", keyring.KeyringFile{
			SchemaVersion: keyring.SchemaVersion,
			Roots:         []keyring.RootOfTrustRecord{{}},
		}, "unsupported KEK type"},
	}
	if runtime.GOOS != "darwin" {
		cases = append(cases, struct {
			name    string
			kf      keyring.KeyringFile
			wantSub string
		}{"keychain off macOS", keyring.KeyringFile{SchemaVersion: keyring.SchemaVersion, KEKType: "keychain"}, "only available on macOS"})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			krPath := filepath.Join(t.TempDir(), "keyring.json")
			bkWriteKeyringFile(t, krPath, tc.kf)
			_, err := bkFileFactory(t)(context.Background(), backend.BackendConfig{
				Name:     "file",
				Settings: map[string]interface{}{"data_dir": t.TempDir(), "keyring_path": krPath},
			})
			if !errors.Is(err, backend.ErrBootstrapRequired) {
				t.Fatalf("got %v, want ErrBootstrapRequired", err)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not contain %q", err, tc.wantSub)
			}
		})
	}
}

func TestFileFactory_RootsKeyringPassphraseRoot(t *testing.T) {
	krPath := filepath.Join(t.TempDir(), "keyring.json")
	raw := `{"schema_version":2,"roots":[{"spec":{"id":"r1","type":"passphrase"}}]}`
	if err := os.WriteFile(krPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := bkFileFactory(t)(context.Background(), backend.BackendConfig{
		Name:     "file",
		Settings: map[string]interface{}{"data_dir": t.TempDir(), "keyring_path": krPath},
	})
	if !errors.Is(err, backend.ErrBootstrapRequired) || !strings.Contains(err.Error(), "passphrase KEK requires interactive input") {
		t.Fatalf("got %v, want passphrase bootstrap error derived from roots[0]", err)
	}
}

func TestFileFactory_CorruptKeyringHeader(t *testing.T) {
	krPath := filepath.Join(t.TempDir(), "keyring.json")
	if err := os.WriteFile(krPath, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := bkFileFactory(t)(context.Background(), backend.BackendConfig{
		Name:     "file",
		Settings: map[string]interface{}{"data_dir": t.TempDir(), "keyring_path": krPath},
	})
	if !errors.Is(err, backend.ErrBootstrapRequired) || !strings.Contains(err.Error(), "read keyring header") {
		t.Fatalf("got %v, want bootstrap error about the keyring header", err)
	}
}

func TestFileFactory_KeyringStatError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ENOTDIR semantics differ on windows")
	}
	notDir := filepath.Join(t.TempDir(), "plainfile")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := bkFileFactory(t)(context.Background(), backend.BackendConfig{
		Name:     "file",
		Settings: map[string]interface{}{"data_dir": t.TempDir(), "keyring_path": filepath.Join(notDir, "keyring.json")},
	})
	if err == nil || !strings.Contains(err.Error(), "stat keyring") {
		t.Fatalf("got %v, want stat keyring error", err)
	}
	if errors.Is(err, backend.ErrBootstrapRequired) {
		t.Error("a non-absence stat failure must not be reported as missing bootstrap")
	}
}

func TestFileFactory_EmptyDataDirDefaultsUnderHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	idPath := filepath.Join(home, "identity")
	bkWriteIdentity(t, idPath, "home-identity-"+strings.Repeat("h", 40))
	krPath := filepath.Join(home, "kr", "keyring.json")
	bkAgeKeyring(t, krPath, idPath)
	t.Setenv("KEYLATCH_AGE_IDENTITY", idPath)

	b, err := bkFileFactory(t)(context.Background(), backend.BackendConfig{
		Name:     "file",
		Settings: map[string]interface{}{"keyring_path": krPath},
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	direr, ok := b.(interface{ Dir() string })
	if !ok {
		t.Fatalf("backend %T has no Dir()", b)
	}
	if want := home + "/.keylatch/vault"; direr.Dir() != want {
		t.Fatalf("Dir() = %q, want %q", direr.Dir(), want)
	}
	if fi, err := os.Stat(direr.Dir()); err != nil || !fi.IsDir() {
		t.Fatalf("default data dir not created: %v", err)
	}
}

func TestFileFactory_WrongSettingType(t *testing.T) {
	_, err := bkFileFactory(t)(context.Background(), backend.BackendConfig{
		Name:     "file",
		Settings: map[string]interface{}{"data_dir": []int{1}},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid settings") {
		t.Fatalf("got %v, want invalid settings error", err)
	}
}
