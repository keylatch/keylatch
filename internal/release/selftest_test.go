//go:build release

package release_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/release"
)

func TestVerifyNoCanary_Clean(t *testing.T) {
	if err := release.VerifyNoCanary([]byte("clean data")); err != nil {
		t.Errorf("expected nil, got: %v", err)
	}
}

func TestVerifyNoCanary_ContainsSentinel(t *testing.T) {
	if err := release.VerifyNoCanary([]byte("contains KEYLATCH_CANARY_ oops")); err == nil {
		t.Error("expected error for canary sentinel, got nil")
	}
}

func TestVersionIsSet_DevDefault(t *testing.T) {
	// In test builds without ldflags, version.Version is still "dev".
	if err := release.VersionIsSet(); err == nil {
		t.Error("expected error when version is 'dev', got nil")
	}
}
