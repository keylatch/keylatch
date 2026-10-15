package dispatch

import (
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/config"
)

func TestBuildSettings_ExternalBackendEnv(t *testing.T) {
	env := func(k string) string {
		values := map[string]string{
			"KEYLATCH_VAULT_ADDR":              "https://vault.example",
			"KEYLATCH_VAULT_TOKEN":             "vault-token",
			"KEYLATCH_AWS_SM_REGION":           "eu-central-1",
			"KEYLATCH_AWS_ACCESS_KEY_ID":       "AKIAEXAMPLE",
			"KEYLATCH_AWS_SECRET_ACCESS_KEY":   "secret",
			"KEYLATCH_GCP_PROJECT_ID":          "project-1",
			"KEYLATCH_AZURE_KV_URL":            "https://example.vault.azure.net",
			"KEYLATCH_DOPPLER_TOKEN":           "dp.st.test",
			"KEYLATCH_DOPPLER_PROJECT":         "proj",
			"KEYLATCH_DOPPLER_CONFIG":          "dev",
			"KEYLATCH_INFISICAL_CLIENT_ID":     "client",
			"KEYLATCH_INFISICAL_CLIENT_SECRET": "client-secret",
			"KEYLATCH_OP_CONNECT_URL":          "http://127.0.0.1:8080",
			"KEYLATCH_OP_CONNECT_TOKEN":        "connect-token",
			"KEYLATCH_OP_CONNECT_VAULT_ID":     "vault-id",
		}
		return values[k]
	}

	cfg := config.Default()
	optIn := map[string]config.BackendCredentials{}
	for _, id := range config.RemoteBackendIDs {
		optIn[id] = config.BackendCredentials{AllowEnvCredentials: true}
	}
	cfg.Backends = optIn
	resolve := func(name string) map[string]interface{} {
		s, err := resolveSettings(name, cfg, env)
		if err != nil {
			t.Fatalf("resolveSettings(%s): %v", name, err)
		}
		return s
	}

	assertSetting(t, resolve("vault"), "address", "https://vault.example")
	assertSetting(t, resolve("vault"), "token", "vault-token")
	assertSetting(t, resolve("aws-sm"), "region", "eu-central-1")
	assertSetting(t, resolve("aws-sm"), "access_key_id", "AKIAEXAMPLE")
	assertSetting(t, resolve("aws-sm"), "secret_access_key", "secret")
	assertSetting(t, resolve("gcp-sm"), "project_id", "project-1")
	assertSetting(t, resolve("azure-kv"), "vault_url", "https://example.vault.azure.net")
	assertSetting(t, resolve("doppler"), "token", "dp.st.test")
	assertSetting(t, resolve("doppler"), "project", "proj")
	assertSetting(t, resolve("doppler"), "config", "dev")
	assertSetting(t, resolve("infisical"), "client_id", "client")
	assertSetting(t, resolve("infisical"), "client_secret", "client-secret")
	assertSetting(t, resolve("op-connect"), "connect_url", "http://127.0.0.1:8080")
	assertSetting(t, resolve("op-connect"), "token", "connect-token")
	assertSetting(t, resolve("op-connect"), "vault_id", "vault-id")

	// The settings builder alone never carries a credential.
	for _, name := range []string{"vault", "aws-sm", "doppler", "infisical", "op-connect"} {
		for _, c := range envCredentials[name] {
			if _, ok := buildSettings(name, cfg, env)[c.field]; ok {
				t.Errorf("buildSettings(%s) carries credential %s", name, c.field)
			}
		}
	}
}

func TestBuildSettings_FileBackendUsesVaultPathEnv(t *testing.T) {
	env := func(k string) string {
		values := map[string]string{
			"KEYLATCH_CONFIG_DIR": "/tmp/keylatch-config",
			"KEYLATCH_VAULT_PATH": "/tmp/keylatch-vault",
			"KEYLATCH_DATA_DIR":   "/tmp/legacy-data",
		}
		return values[k]
	}

	cfg := config.Default()
	assertSetting(t, buildSettings("file", cfg, env), "data_dir", "/tmp/keylatch-vault")
}

func TestBuildSettings_FileBackendFallsBackToDataDirEnv(t *testing.T) {
	env := func(k string) string {
		values := map[string]string{
			"KEYLATCH_CONFIG_DIR": "/tmp/keylatch-config",
			"KEYLATCH_DATA_DIR":   "/tmp/legacy-data",
		}
		return values[k]
	}

	cfg := config.Default()
	assertSetting(t, buildSettings("file", cfg, env), "data_dir", "/tmp/legacy-data")
}

func TestBuildSettings_FileBackendFallsBackToConfigDirVault(t *testing.T) {
	env := func(k string) string {
		values := map[string]string{
			"KEYLATCH_CONFIG_DIR": "/tmp/keylatch-config",
		}
		return values[k]
	}

	cfg := config.Default()
	assertSetting(t, buildSettings("file", cfg, env), "data_dir", "/tmp/keylatch-config/vault")
}

func assertSetting(t *testing.T, settings map[string]interface{}, key, want string) {
	t.Helper()
	// Path-valued settings are built with filepath.Join, so they use the OS
	// separator (backslashes on Windows). Compare in slash form so the
	// forward-slash `want` fixtures hold on every platform; ToSlash is a
	// no-op for non-path values.
	got, _ := settings[key].(string)
	if filepath.ToSlash(got) != want {
		t.Fatalf("settings[%q] = %q, want %q", key, got, want)
	}
}
