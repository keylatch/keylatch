package doctor

import (
	"context"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/paths"
)

func TestBackendEnvCredentialsWarns(t *testing.T) {
	dir := t.TempDir()
	env := func(k string) string {
		if k == "KEYLATCH_CONFIG_DIR" {
			return dir
		}
		return ""
	}
	cfg := config.Default()
	if err := config.Save(paths.Config(env), cfg); err != nil {
		t.Fatal(err)
	}
	if st := checkBackendEnvCredentials(env)(context.Background()); !st.OK || st.Warn {
		t.Fatalf("no opt-in: %+v", st)
	}

	cfg.Backends = map[string]config.BackendCredentials{
		"vault":   {AllowEnvCredentials: true},
		"doppler": {AllowEnvCredentials: true, CredentialRef: "stored"},
		"awssm":   {AllowEnvCredentials: true},
	}
	if err := config.Save(paths.Config(env), cfg); err != nil {
		t.Fatal(err)
	}
	st := checkBackendEnvCredentials(env)(context.Background())
	if !st.OK || !st.Warn {
		t.Fatalf("opt-in must warn, not fail: %+v", st)
	}
	if !strings.Contains(st.Detail, "awssm, vault") || strings.Contains(st.Detail, "doppler") {
		t.Fatalf("detail = %q, want awssm and vault only", st.Detail)
	}
}
