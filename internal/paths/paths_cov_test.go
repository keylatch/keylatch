package paths_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/paths"
)

func fixedLookup(vals map[string]string) paths.Lookup {
	return func(k string) string { return vals[k] }
}

// TestPathGetters_UnderConfigDir verifies every path getter resolves under
// the KEYLATCH_CONFIG_DIR override and that no two getters collide.
func TestPathGetters_UnderConfigDir(t *testing.T) {
	t.Parallel()
	base := filepath.Join("/", "cfgbase")
	lk := fixedLookup(map[string]string{"KEYLATCH_CONFIG_DIR": base})

	cases := []struct {
		name string
		got  string
		leaf string
	}{
		{"ConfigDir", paths.ConfigDir(lk), ""},
		{"Config", paths.Config(lk), "config.json"},
		{"Vault", paths.Vault(lk), "vault"},
		{"Audit", paths.Audit(lk), ""},
		{"AuditSalt", paths.AuditSalt(lk), ""},
		{"Policy", paths.Policy(lk), ""},
		{"Grants", paths.Grants(lk), ""},
		{"GrantsDir", paths.GrantsDir(lk), ""},
		{"GrantAccessorKey", paths.GrantAccessorKey(lk), ""},
		{"Actors", paths.Actors(lk), ""},
		{"Projects", paths.Projects(lk), ""},
		{"KeyringDir", paths.KeyringDir(lk), ""},
		{"KeyringPath", paths.KeyringPath(lk), ""},
		{"KeyringIdentityPath", paths.KeyringIdentityPath(lk), ""},
		{"GatewayDir", paths.GatewayDir(lk), ""},
		{"GatewayConfig", paths.GatewayConfig(lk), ""},
		{"GatewaySigningKey", paths.GatewaySigningKey(lk), ""},
		{"GatewayPID", paths.GatewayPID(lk), ""},
		{"GatewayLog", paths.GatewayLog(lk), ""},
		{"GatewayTokens", paths.GatewayTokens(lk), ""},
		{"GatewayRules", paths.GatewayRules(lk), ""},
		{"ApprovalsDir", paths.ApprovalsDir(lk), ""},
		{"Sessions", paths.Sessions(lk), ""},
		{"Receipts", paths.Receipts(lk), ""},
		{"DaemonState", paths.DaemonState(lk), ""},
	}
	for _, tc := range cases {
		if tc.got == "" {
			t.Errorf("%s returned empty path", tc.name)
			continue
		}
		if !strings.HasPrefix(tc.got, base) {
			t.Errorf("%s = %q, want prefix %q", tc.name, tc.got, base)
		}
		if tc.leaf != "" && filepath.Base(tc.got) != tc.leaf {
			t.Errorf("%s leaf = %q, want %q", tc.name, filepath.Base(tc.got), tc.leaf)
		}
	}

	// Distinctness: no two getters may collide on the same path.
	seen := map[string]string{}
	for _, tc := range cases {
		if prev, dup := seen[tc.got]; dup {
			t.Errorf("path collision: %s and %s both return %q", prev, tc.name, tc.got)
		}
		seen[tc.got] = tc.name
	}
}

// TestConfigDir_NoOverride exercises the platform fallback path.
func TestConfigDir_NoOverride(t *testing.T) {
	t.Parallel()
	got := paths.ConfigDir(fixedLookup(nil))
	if got == "" {
		t.Fatal("ConfigDir must not be empty without override")
	}
	if !filepath.IsAbs(got) {
		t.Errorf("ConfigDir = %q, want absolute path", got)
	}
}

// TestConfigDir_XDGBranch covers the XDG lookup (effective on Linux; other
// platforms must still return a non-empty path).
func TestConfigDir_XDGBranch(t *testing.T) {
	t.Parallel()
	got := paths.ConfigDir(fixedLookup(map[string]string{"XDG_CONFIG_HOME": "/xdg"}))
	if got == "" {
		t.Fatal("ConfigDir must not be empty with XDG set")
	}
}

// TestAssertSafeModes_ErrorTypes covers the exported error types.
func TestAssertSafeModes_ErrorTypes(t *testing.T) {
	t.Parallel()
	ue := &paths.UnsafeMode{}
	if ue.Error() == "" {
		t.Error("UnsafeMode.Error must be non-empty")
	}
	pnf := &paths.PathNotFound{}
	if pnf.Error() == "" {
		t.Error("PathNotFound.Error must be non-empty")
	}
}

// TestPathGetters_PerPathOverrides verifies each getter honours its own
// override variable, bypassing ConfigDir entirely.
func TestPathGetters_PerPathOverrides(t *testing.T) {
	t.Parallel()
	const want = "/override/target"
	cases := []struct {
		key string
		fn  func(paths.Lookup) string
	}{
		{"KEYLATCH_CONFIG", paths.Config},
		{"KEYLATCH_VAULT_PATH", paths.Vault},
		{"KEYLATCH_AUDIT_PATH", paths.Audit},
		{"KEYLATCH_AUDIT_SALT_PATH", paths.AuditSalt},
		{"KEYLATCH_POLICY_PATH", paths.Policy},
		{"KEYLATCH_GRANTS_PATH", paths.Grants},
		{"KEYLATCH_GRANTS_DIR", paths.GrantsDir},
		{"KEYLATCH_GRANT_ACCESSOR_KEY_PATH", paths.GrantAccessorKey},
		{"KEYLATCH_ACTORS_PATH", paths.Actors},
		{"KEYLATCH_PROJECTS_PATH", paths.Projects},
		{"KEYLATCH_KEYRING_DIR", paths.KeyringDir},
		{"KEYLATCH_KEYRING_PATH", paths.KeyringPath},
		{"KEYLATCH_KEYRING_IDENTITY_PATH", paths.KeyringIdentityPath},
		{"KEYLATCH_GATEWAY_DIR", paths.GatewayDir},
		{"KEYLATCH_GATEWAY_CONFIG", paths.GatewayConfig},
		{"KEYLATCH_GATEWAY_SIGNING_KEY", paths.GatewaySigningKey},
		{"KEYLATCH_GATEWAY_PID", paths.GatewayPID},
		{"KEYLATCH_GATEWAY_LOG", paths.GatewayLog},
		{"KEYLATCH_GATEWAY_TOKENS", paths.GatewayTokens},
		{"KEYLATCH_GATEWAY_RULES", paths.GatewayRules},
		{"KEYLATCH_APPROVALS_DIR", paths.ApprovalsDir},
		{"KEYLATCH_SESSIONS_PATH", paths.Sessions},
		{"KEYLATCH_RECEIPTS_PATH", paths.Receipts},
		{"KEYLATCH_DAEMON_STATE_PATH", paths.DaemonState},
	}
	for _, tc := range cases {
		lk := fixedLookup(map[string]string{tc.key: want})
		if got := tc.fn(lk); got != want {
			t.Errorf("%s override: got %q, want %q", tc.key, got, want)
		}
	}
}

// TestAssertSafeModes_Behaviour covers the not-found, safe, and unsafe paths.
func TestAssertSafeModes_Behaviour(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Not found.
	var pnf *paths.PathNotFound
	err := paths.AssertSafeModes(filepath.Join(dir, "missing"))
	if !errors.As(err, &pnf) {
		t.Errorf("missing path: got %v, want *PathNotFound", err)
	}

	// Safe file (0600).
	safe := filepath.Join(dir, "safe")
	if err := os.WriteFile(safe, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := paths.AssertSafeModes(safe); err != nil {
		t.Errorf("0600 file: unexpected error %v", err)
	}

	// Safe dir (0700).
	safeDir := filepath.Join(dir, "safedir")
	if err := os.Mkdir(safeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := paths.AssertSafeModes(safeDir); err != nil {
		t.Errorf("0700 dir: unexpected error %v", err)
	}

	if runtime.GOOS == "windows" {
		return // mode bits not enforced on NTFS
	}

	// Unsafe file (0644).
	unsafe := filepath.Join(dir, "unsafe")
	if err := os.WriteFile(unsafe, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var um *paths.UnsafeMode
	if err := paths.AssertSafeModes(unsafe); !errors.As(err, &um) {
		t.Errorf("0644 file: got %v, want *UnsafeMode", err)
	}

	// Unsafe dir (0755).
	unsafeDir := filepath.Join(dir, "unsafedir")
	if err := os.Mkdir(unsafeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := paths.AssertSafeModes(unsafeDir); !errors.As(err, &um) {
		t.Errorf("0755 dir: got %v, want *UnsafeMode", err)
	}
}
