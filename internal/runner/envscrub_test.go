package runner

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runtime"
)

var credentialEnvNames = []string{
	"BW_SESSION", "BW_CLIENTSECRET", "BWS_ACCESS_TOKEN", "OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_TOKEN",
	"OP_SESSION_myaccount", "VAULT_TOKEN", "VAULT_ROLE_ID", "VAULT_SECRET_ID",
	"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AZURE_CLIENT_SECRET",
	"GOOGLE_APPLICATION_CREDENTIALS", "DOPPLER_TOKEN", "INFISICAL_CLIENT_ID", "INFISICAL_CLIENT_SECRET",
	"KEYLATCH_BACKEND", "KEYLATCH_VAULT_TOKEN",
}

func setCredentialEnv(t *testing.T) {
	t.Helper()
	for _, n := range credentialEnvNames {
		t.Setenv(n, "synthetic-"+n)
	}
	t.Setenv("PATH_KEEP_ME", "kept")
}

func assertScrubbed(t *testing.T, env []string) {
	t.Helper()
	for _, e := range env {
		name, _, _ := strings.Cut(e, "=")
		for _, banned := range credentialEnvNames {
			if name == banned {
				t.Errorf("child environment still has %s", name)
			}
		}
	}
}

// A child never sees backend credentials or Keylatch configuration, even when
// the parent exported them.
func TestChildEnvScrubbed(t *testing.T) {
	setCredentialEnv(t)

	t.Run("ScrubChildEnv", func(t *testing.T) {
		in := []string{"A=1", "VAULT_TOKEN=x", "OP_SESSION_acct=y", "KEYLATCH_DATA_DIR=/v", "PATH=/bin"}
		got := ScrubChildEnv(in)
		if strings.Join(got, ",") != "A=1,PATH=/bin" {
			t.Errorf("ScrubChildEnv = %v", got)
		}
	})

	t.Run("gateway session", func(t *testing.T) {
		env := gatewayTypedChildEnv(registry.ConnectionTemplate{}, "http://127.0.0.1:7878", "scoped", false, nil)
		assertScrubbed(t, env)
		clean := GatewaySessionEnv(runtime.RuntimeGatewaySDK, registry.ConnectionTemplate{Provider: "p"}, "http://127.0.0.1:1", "scoped").
			Apply(envFromTest(), true, []string{"AWS_ACCESS_KEY_ID", "KEYLATCH_BACKEND"})
		assertScrubbed(t, clean)
	})

	t.Run("running child", func(t *testing.T) {
		path, err := exec.LookPath("env")
		if err != nil {
			t.Skip("no env binary")
		}
		var out bytes.Buffer
		d := NewGatewayTypedDriver(auditGateway{}, make([]byte, 32), filepath.Join(t.TempDir(), "tokens.json"))
		if _, err := d.Run(context.Background(), ExecRequest{Command: []string{path}, Stdout: &out}, registry.ConnectionTemplate{Provider: "audit"}); err != nil {
			t.Fatal(err)
		}
		assertScrubbed(t, strings.Split(out.String(), "\n"))
		if !strings.Contains(out.String(), "PATH_KEEP_ME=kept") {
			t.Errorf("unrelated variables were removed:\n%s", out.String())
		}
	})
}

func envFromTest() []string {
	var out []string
	for _, n := range credentialEnvNames {
		out = append(out, n+"=synthetic-"+n)
	}
	return append(out, "PATH=/usr/bin")
}
