package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func cdWriteKeyring(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "keyring", "keyring.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil { //nolint:gosec // permissions are asserted to be tightened
		t.Fatal(err)
	}
	return p
}

func TestUpgradeTrust_UpgradesLegacyKeyring(t *testing.T) {
	cdIsolate(t)
	kr := cdWriteKeyring(t, `{"schema_version":1,"kek_type":"passphrase","kek_id":"kek-1",
		"terms":[{"term":1,"wrapped_dek":"d2Rr"},{"term":2,"wrapped_dek":""},"junk"],"other":"keep"}`)

	r := cdExec(t, newBackendUpgradeTrustCmd(), nil, "--keyring", kr)
	if r.e != nil {
		t.Fatalf("upgrade: %v", r.e)
	}
	if !strings.Contains(r.out, "from schema v1 to v2 (kek_type=passphrase") {
		t.Fatalf("unexpected output %q", r.out)
	}
	data, err := os.ReadFile(kr)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		SchemaVersion int    `json:"schema_version"`
		Other         string `json:"other"`
		Roots         []struct {
			Spec        map[string]string `json:"spec"`
			WrappedDEKs map[string]string `json:"wrapped_deks"`
		} `json:"roots"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("parse upgraded keyring: %v", err)
	}
	if got.SchemaVersion != 2 || got.Other != "keep" || len(got.Roots) != 1 {
		t.Fatalf("unexpected upgraded keyring: %s", data)
	}
	root := got.Roots[0]
	if root.Spec["id"] != "kek-1" || root.Spec["status"] != "active" || root.Spec["label"] != "migrated-passphrase" || root.Spec["type"] == "" {
		t.Fatalf("unexpected root spec %v", root.Spec)
	}
	if len(root.WrappedDEKs) != 1 || root.WrappedDEKs["1"] != "d2Rr" {
		t.Fatalf("only non-empty wrapped DEKs must migrate: %v", root.WrappedDEKs)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(kr); fi.Mode().Perm() != 0o600 {
			t.Fatalf("keyring mode = %o, want 0600", fi.Mode().Perm())
		}
	}

	r = cdExec(t, newBackendUpgradeTrustCmd(), nil, "--keyring", kr, "--json")
	var res map[string]any
	if err := json.Unmarshal([]byte(r.out), &res); err != nil || res["action"] != "no-op" || res["schema_before"] != float64(2) {
		t.Fatalf("second run must be a no-op: %v %q", err, r.out)
	}
}

func TestUpgradeTrust_DryRunLeavesFileUntouched(t *testing.T) {
	cdIsolate(t)
	body := `{"schema_version":1,"kek_type":"keychain"}`
	kr := cdWriteKeyring(t, body)
	r := cdExec(t, newBackendUpgradeTrustCmd(), nil, "--keyring", kr, "--dry-run", "--json")
	if r.e != nil {
		t.Fatal(r.e)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(r.out), &res); err != nil || res["action"] != "dry-run" || res["dry_run"] != true || res["schema_after"] != float64(2) {
		t.Fatalf("unexpected dry-run result %q", r.out)
	}
	if after, _ := os.ReadFile(kr); string(after) != body {
		t.Fatalf("dry-run modified keyring: %s", after)
	}
}

func TestUpgradeTrust_Errors(t *testing.T) {
	cdIsolate(t)
	cases := []struct {
		name    string
		path    func(t *testing.T) string
		wantErr string
	}{
		{"missing file", func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.json") }, "read keyring"},
		{"bad json", func(t *testing.T) string { return cdWriteKeyring(t, "{") }, "parse keyring"},
		{"v1 without kek_type", func(t *testing.T) string { return cdWriteKeyring(t, `{"schema_version":1}`) }, "missing kek_type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := cdExec(t, newBackendUpgradeTrustCmd(), nil, "--keyring", tc.path(t))
			if r.e == nil || !strings.Contains(r.e.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", r.e, tc.wantErr)
			}
		})
	}
}

func TestUpgradeTrust_DefaultKeyringPathUnderVault(t *testing.T) {
	cdIsolate(t)
	vaultDir := t.TempDir()
	t.Setenv("KEYLATCH_VAULT_PATH", vaultDir)
	kr := filepath.Join(vaultDir, "keyring", "keyring.json")
	if err := os.MkdirAll(filepath.Dir(kr), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kr, []byte(`{"schema_version":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r := cdExec(t, newBackendUpgradeTrustCmd(), nil)
	if r.e != nil || !strings.Contains(r.out, "already at schema v2") {
		t.Fatalf("err=%v out=%q", r.e, r.out)
	}
}

func TestUpgradeTrust_WriteFailureLeavesKeyringIntact(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX directory permissions enforced for a non-root user")
	}
	cdIsolate(t)
	body := `{"schema_version":1,"kek_type":"passphrase"}`
	kr := cdWriteKeyring(t, body)
	dir := filepath.Dir(kr)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	r := cdExec(t, newBackendUpgradeTrustCmd(), nil, "--keyring", kr)
	if r.e == nil || !strings.Contains(r.e.Error(), "backend upgrade-trust: write") {
		t.Fatalf("err = %v, want write failure", r.e)
	}
	if after, _ := os.ReadFile(kr); string(after) != body {
		t.Fatalf("failed upgrade must not alter keyring: %s", after)
	}
}
