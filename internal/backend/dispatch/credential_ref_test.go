package dispatch

import (
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/backend/credref"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

var testKEKParams = argon2.Params{Time: 1, Memory: 64 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32}

func useTestKEK(t *testing.T) kek.KEK {
	t.Helper()
	k, err := kek.PassphraseKEK([]byte("test"), make([]byte, 32), testKEKParams)
	if err != nil {
		t.Fatal(err)
	}
	prev := credentialKEK
	credentialKEK = func(llmcontext.Lookup) (kek.KEK, error) { return k, nil }
	t.Cleanup(func() { credentialKEK = prev })
	return k
}

func envOf(m map[string]string) llmcontext.Lookup {
	return func(k string) string { return m[k] }
}

// With a credential_ref set and the environment variable unset, the backend
// still gets its credential, and a stale variable in the environment loses to
// the stored value.
func TestCredentialRefPreferred(t *testing.T) {
	k := useTestKEK(t)
	dir := t.TempDir()
	env := map[string]string{"KEYLATCH_CONFIG_DIR": dir}
	if err := credref.Save(envOf(env), k, "prod-vault", map[string]string{"token": "stored-token", "role_id": "r", "secret_id": "s"}); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Backends = map[string]config.BackendCredentials{"vault": {CredentialRef: "prod-vault"}}

	got, err := resolveSettings("vault", cfg, envOf(env))
	if err != nil {
		t.Fatal(err)
	}
	if got["token"] != "stored-token" || got["role_id"] != "r" || got["secret_id"] != "s" {
		t.Fatalf("settings = %v, want the stored credential", got)
	}

	env["VAULT_TOKEN"] = "ambient-token"
	got, err = resolveSettings("vault", cfg, envOf(env))
	if err != nil || got["token"] != "stored-token" {
		t.Fatalf("with an ambient token: %v %v", got, err)
	}

	// The aws-sm id in the config is awssm.
	cfg.Backends = map[string]config.BackendCredentials{"awssm": {CredentialRef: "aws"}}
	if err := credref.Save(envOf(env), k, "aws", map[string]string{"access_key_id": "AKIA", "secret_access_key": "sec"}); err != nil {
		t.Fatal(err)
	}
	got, err = resolveSettings("aws-sm", cfg, envOf(env))
	if err != nil || got["access_key_id"] != "AKIA" || got["secret_access_key"] != "sec" {
		t.Fatalf("aws settings = %v %v", got, err)
	}

	cfg.Backends = map[string]config.BackendCredentials{"vault": {CredentialRef: "missing"}}
	if _, err := resolveSettings("vault", cfg, envOf(env)); !errors.Is(err, credref.ErrNotFound) {
		t.Fatalf("missing reference: %v", err)
	}
}

func TestCredentialRefForOnePassword(t *testing.T) {
	k := useTestKEK(t)
	env := map[string]string{"KEYLATCH_CONFIG_DIR": t.TempDir(), "OP_SERVICE_ACCOUNT_TOKEN": "ambient"}
	if err := credref.Save(envOf(env), k, "op-sa", map[string]string{"service_account_token": "stored-sa"}); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Backends = map[string]config.BackendCredentials{"op": {CredentialRef: "op-sa"}}
	s, err := resolveSettings("op", cfg, envOf(env))
	if err != nil {
		t.Fatal(err)
	}
	lookup, _ := s["env"].(llmcontext.Lookup)
	if lookup == nil || lookup("OP_SERVICE_ACCOUNT_TOKEN") != "stored-sa" || lookup("KEYLATCH_CONFIG_DIR") != env["KEYLATCH_CONFIG_DIR"] {
		t.Fatalf("op env lookup does not overlay the stored token")
	}
}

// Credentials in the environment are refused unless the config opts in.
func TestEnvCredentialsNeedOptIn(t *testing.T) {
	env := envOf(map[string]string{"VAULT_TOKEN": "ambient", "KEYLATCH_VAULT_ADDR": "https://v"})

	_, err := resolveSettings("vault", config.Default(), env)
	if !errors.Is(err, ErrEnvCredentials) {
		t.Fatalf("env credentials without opt-in: %v", err)
	}

	cfg := config.Default()
	cfg.Backends = map[string]config.BackendCredentials{"vault": {AllowEnvCredentials: true}}
	got, err := resolveSettings("vault", cfg, env)
	if err != nil || got["token"] != "ambient" {
		t.Fatalf("with allow_env_credentials: %v %v", got, err)
	}

	// No credential in the environment: nothing to refuse.
	if _, err := resolveSettings("vault", config.Default(), envOf(map[string]string{"KEYLATCH_VAULT_ADDR": "https://v"})); err != nil {
		t.Fatalf("no credentials at all: %v", err)
	}
}
