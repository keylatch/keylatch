package paths

import (
	"os"
	"path/filepath"
	"testing"
)

func writeKeyringFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func lookupFrom(vars map[string]string) Lookup {
	return func(k string) string { return vars[k] }
}

func TestResolveKeyringPath(t *testing.T) {
	cases := map[string]struct {
		canonical, legacy bool
		wantLegacy        bool
	}{
		"neither exists":        {},
		"bootstrap only":        {canonical: true},
		"legacy only":           {legacy: true, wantLegacy: true},
		"both prefer bootstrap": {canonical: true, legacy: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			lookup := lookupFrom(map[string]string{"KEYLATCH_CONFIG_DIR": dir})
			canonical := filepath.Join(dir, "keyring", "keyring.json")
			legacy := filepath.Join(dir, "vault", "keyring", "keyring.json")
			if got := KeyringPath(lookup); got != canonical {
				t.Fatalf("KeyringPath = %q, want %q", got, canonical)
			}
			if got := LegacyKeyringPath(lookup); got != legacy {
				t.Fatalf("LegacyKeyringPath = %q, want %q", got, legacy)
			}
			if tc.canonical {
				writeKeyringFile(t, canonical)
			}
			if tc.legacy {
				writeKeyringFile(t, legacy)
			}
			want := canonical
			if tc.wantLegacy {
				want = legacy
			}
			if got := ResolveKeyringPath(lookup); got != want {
				t.Fatalf("ResolveKeyringPath = %q, want %q", got, want)
			}
		})
	}
}

func TestResolveKeyringPathHonoursOverrides(t *testing.T) {
	dir := t.TempDir()
	writeKeyringFile(t, filepath.Join(dir, "vault", "keyring", "keyring.json"))
	override := filepath.Join(dir, "elsewhere", "kr.json")
	overrideDir := filepath.Join(dir, "krdir")

	for _, tc := range []struct {
		key, value, want string
	}{
		{"KEYLATCH_KEYRING_PATH", override, override},
		{"KEYLATCH_KEYRING_DIR", overrideDir, filepath.Join(overrideDir, "keyring.json")},
	} {
		lookup := lookupFrom(map[string]string{"KEYLATCH_CONFIG_DIR": dir, tc.key: tc.value})
		if got := ResolveKeyringPath(lookup); got != tc.want {
			t.Errorf("%s: ResolveKeyringPath = %q, want %q", tc.key, got, tc.want)
		}
	}
}

func TestResolveKeyringPathFollowsVaultOverride(t *testing.T) {
	vault := filepath.Join(t.TempDir(), "v")
	legacy := filepath.Join(vault, "keyring", "keyring.json")
	writeKeyringFile(t, legacy)
	lookup := lookupFrom(map[string]string{"KEYLATCH_CONFIG_DIR": t.TempDir(), "KEYLATCH_VAULT_PATH": vault})
	if got := ResolveKeyringPath(lookup); got != legacy {
		t.Fatalf("ResolveKeyringPath = %q, want %q", got, legacy)
	}
}
