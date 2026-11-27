package ui

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
)

func lookupFor(dir string) func(string) string {
	return func(k string) string {
		switch k {
		case "HOME", "USERPROFILE":
			return dir
		case "KEYLATCH_CONFIG":
			return filepath.Join(dir, "config.json")
		case "KEYLATCH_BACKEND":
			return "file"
		}
		return ""
	}
}

func TestConfiguredStore_UnconfiguredReturnsError(t *testing.T) {
	s := &configuredStore{env: lookupFor(t.TempDir())}
	if err := s.Set(context.Background(), "default/demo/key", []byte("v"), backend.Meta{}); err == nil {
		t.Fatal("Set must fail when no backend is configured")
	}
}
