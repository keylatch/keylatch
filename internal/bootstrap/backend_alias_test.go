package bootstrap_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/bootstrap"
	"github.com/keylatch/keylatch/internal/config"
)

func TestRun_CanonicalizesBackendAlias(t *testing.T) {
	dir := t.TempDir()
	env := func(k string) string {
		if k == "KEYLATCH_CONFIG_DIR" {
			return dir
		}
		return ""
	}

	_, err := bootstrap.Run(context.Background(), bootstrap.Options{
		Backend: "awssm",
		Env:     env,
	})
	if err != nil {
		t.Fatalf("bootstrap awssm alias: %v", err)
	}

	cfg, err := config.Load(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Backend != "aws-sm" {
		t.Fatalf("backend = %q, want aws-sm", cfg.Backend)
	}
	if _, err := os.Stat(filepath.Join(dir, "keyring", "keyring.json")); !os.IsNotExist(err) {
		t.Fatalf("external backend bootstrap should not create file keyring, stat err=%v", err)
	}
}
