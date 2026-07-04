package dispatch

import (
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

	assertSetting(t, buildSettings("vault", cfg, env), "address", "https://vault.example")
	assertSetting(t, buildSettings("vault", cfg, env), "token", "vault-token")
	assertSetting(t, buildSettings("aws-sm", cfg, env), "region", "eu-central-1")
	assertSetting(t, buildSettings("aws-sm", cfg, env), "access_key_id", "AKIAEXAMPLE")
	assertSetting(t, buildSettings("aws-sm", cfg, env), "secret_access_key", "secret")
	assertSetting(t, buildSettings("gcp-sm", cfg, env), "project_id", "project-1")
	assertSetting(t, buildSettings("azure-kv", cfg, env), "vault_url", "https://example.vault.azure.net")
	assertSetting(t, buildSettings("doppler", cfg, env), "token", "dp.st.test")
	assertSetting(t, buildSettings("doppler", cfg, env), "project", "proj")
	assertSetting(t, buildSettings("doppler", cfg, env), "config", "dev")
	assertSetting(t, buildSettings("infisical", cfg, env), "client_id", "client")
	assertSetting(t, buildSettings("infisical", cfg, env), "client_secret", "client-secret")
	assertSetting(t, buildSettings("op-connect", cfg, env), "connect_url", "http://127.0.0.1:8080")
	assertSetting(t, buildSettings("op-connect", cfg, env), "token", "connect-token")
	assertSetting(t, buildSettings("op-connect", cfg, env), "vault_id", "vault-id")
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
	if got, _ := settings[key].(string); got != want {
		t.Fatalf("settings[%q] = %q, want %q", key, got, want)
	}
}
