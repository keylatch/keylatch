package dispatch

import (
	"testing"

	"github.com/keylatch/keylatch/internal/config"
)

func bkMapEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestBuildSettings_FileKeyringPathFromEnv(t *testing.T) {
	env := bkMapEnv(map[string]string{
		"KEYLATCH_VAULT_PATH":   "/v",
		"KEYLATCH_KEYRING_PATH": "/kr/keyring",
	})
	s := buildSettings("file", config.Default(), env)
	assertSetting(t, s, "keyring_path", "/kr/keyring")
	assertSetting(t, s, "data_dir", "/v")
}

func TestBuildSettings_FileConfigDataDirWinsOverEnv(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = "/from-config"
	env := bkMapEnv(map[string]string{"KEYLATCH_VAULT_PATH": "/from-env"})
	s := buildSettings("file", cfg, env)
	assertSetting(t, s, "data_dir", "/from-config")
	if _, ok := s["keyring_path"]; ok {
		t.Fatal("keyring_path must be absent when KEYLATCH_KEYRING_PATH is unset")
	}
}

func TestBuildSettings_OPConfigWinsOverEnv(t *testing.T) {
	cfg := config.Default()
	cfg.OP = &config.OPConfig{Vault: "CfgVault", Bin: "/cfg/op"}
	env := bkMapEnv(map[string]string{
		"KEYLATCH_OP_VAULT": "EnvVault",
		"KEYLATCH_OP_BIN":   "/env/op",
	})
	s := buildSettings("op", cfg, env)
	assertSetting(t, s, "vault", "CfgVault")
	assertSetting(t, s, "bin", "/cfg/op")
}

func TestBuildSettings_OPEmptyConfigFallsBackToEnv(t *testing.T) {
	cfg := config.Default()
	cfg.OP = &config.OPConfig{}
	env := bkMapEnv(map[string]string{
		"KEYLATCH_OP_VAULT": "EnvVault",
		"KEYLATCH_OP_BIN":   "/env/op",
	})
	s := buildSettings("op", cfg, env)
	assertSetting(t, s, "vault", "EnvVault")
	assertSetting(t, s, "bin", "/env/op")
}

func TestBuildSettings_BWConfigAndEnvMerge(t *testing.T) {
	cfg := config.Default()
	cfg.BW = &config.BWConfig{Server: "https://cfg.example", Folder: ""}
	env := bkMapEnv(map[string]string{
		"KEYLATCH_BW_SERVER":     "https://env.example",
		"KEYLATCH_BW_FOLDER":     "env-folder",
		"KEYLATCH_BW_COLLECTION": "env-coll",
		"KEYLATCH_BW_BIN":        "/env/bw",
	})
	s := buildSettings("bw", cfg, env)
	assertSetting(t, s, "server", "https://cfg.example")
	assertSetting(t, s, "folder", "env-folder")
	assertSetting(t, s, "collection", "env-coll")
	assertSetting(t, s, "bin", "/env/bw")
}

func TestBuildSettings_CLIBackendsFromEnv(t *testing.T) {
	env := bkMapEnv(map[string]string{
		"KEYLATCH_PROTON_PASS_VAULT":       "pp-vault",
		"KEYLATCH_PROTON_PASS_BIN":         "/bin/pass-cli",
		"KEYLATCH_PROTON_PASS_ITEM_PREFIX": "kl-",
		"KEYLATCH_KEEPER_BIN":              "/bin/keeper",
		"KEYLATCH_KEEPER_ACCOUNT_UID":      "acct",
		"KEYLATCH_LASTPASS_BIN":            "/bin/lpass",
		"KEYLATCH_LASTPASS_USERNAME":       "user@example.test",
	})
	cfg := config.Default()

	pp := buildSettings("proton-pass", cfg, env)
	assertSetting(t, pp, "vault", "pp-vault")
	assertSetting(t, pp, "bin", "/bin/pass-cli")
	assertSetting(t, pp, "item_prefix", "kl-")
	if pp["env"] == nil {
		t.Fatal("proton-pass settings must carry the env lookup")
	}

	kp := buildSettings("keeper", cfg, env)
	assertSetting(t, kp, "bin", "/bin/keeper")
	assertSetting(t, kp, "account_uid", "acct")

	lp := buildSettings("lastpass", cfg, env)
	assertSetting(t, lp, "bin", "/bin/lpass")
	assertSetting(t, lp, "username", "user@example.test")
}

func TestBuildSettings_SecondaryEnvNamesUsedWhenPrimaryUnset(t *testing.T) {
	env := bkMapEnv(map[string]string{
		"VAULT_ADDR":         "https://vault.secondary",
		"AWS_DEFAULT_REGION": "us-west-2",
		"GCLOUD_PROJECT":     "gproj",
		"AZURE_TENANT_ID":    "tenant",
		"DOPPLER_PROJECT":    "dproj",
		"INFISICAL_API_URL":  "https://inf.example",
		"OP_CONNECT_HOST":    "http://connect.example",
	})
	cfg := config.Default()
	assertSetting(t, buildSettings("vault", cfg, env), "address", "https://vault.secondary")
	assertSetting(t, buildSettings("aws-sm", cfg, env), "region", "us-west-2")
	assertSetting(t, buildSettings("gcp-sm", cfg, env), "project_id", "gproj")
	assertSetting(t, buildSettings("azure-kv", cfg, env), "tenant_id", "tenant")
	assertSetting(t, buildSettings("doppler", cfg, env), "project", "dproj")
	assertSetting(t, buildSettings("infisical", cfg, env), "base_url", "https://inf.example")
	assertSetting(t, buildSettings("op-connect", cfg, env), "connect_url", "http://connect.example")
}

func TestBuildSettings_NilEnvLeavesExternalSettingsEmpty(t *testing.T) {
	cfg := config.Default()
	for _, name := range []string{"keeper", "lastpass", "vault", "aws-sm", "gcp-sm", "azure-kv", "doppler", "infisical", "op-connect"} {
		if s := buildSettings(name, cfg, nil); len(s) != 0 {
			t.Errorf("%s with nil env: got %v, want empty settings", name, s)
		}
	}
}

func TestSetIfEnv_NonStringExistingIsOverwritten(t *testing.T) {
	s := map[string]interface{}{"k": 42}
	setIfEnv(s, "k", bkMapEnv(map[string]string{"A": "", "B": "b"}), "A", "B")
	if s["k"] != "b" {
		t.Fatalf("got %v, want b", s["k"])
	}
}

func TestSetIfEnv_NoValueLeavesKeyAbsent(t *testing.T) {
	s := map[string]interface{}{}
	setIfEnv(s, "k", bkMapEnv(nil), "A", "B")
	if _, ok := s["k"]; ok {
		t.Fatal("key must stay absent when no env name resolves")
	}
}

func TestBuildSettings_FileNilEnvUsesProcessEnvironment(t *testing.T) {
	t.Setenv("KEYLATCH_VAULT_PATH", "/process/vault")
	t.Setenv("KEYLATCH_KEYRING_PATH", "/process/keyring")
	s := buildSettings("file", config.Default(), nil)
	assertSetting(t, s, "data_dir", "/process/vault")
	if _, ok := s["keyring_path"]; ok {
		t.Fatal("keyring_path is only taken from an explicit env lookup")
	}
}
