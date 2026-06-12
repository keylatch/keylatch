package gcpsm

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keylatch/keylatch/internal/backend"
)

func TestSecretShortName(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"projects/p/secrets/mysecret":              "mysecret",
		"projects/p/secrets/mysecret/versions/3":   "3",
		"short":                                    "short",
		"projects/p/secrets/deep/extra/components": "components",
	}
	for in, want := range cases {
		if got := secretShortName(in); got != want {
			t.Errorf("secretShortName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsGCPNotFound(t *testing.T) {
	t.Parallel()
	if isGCPNotFound(nil) {
		t.Error("nil must not be not-found")
	}
	if isGCPNotFound(errors.New("plain")) {
		t.Error("plain error must not be not-found")
	}
	if !isGCPNotFound(status.Error(codes.NotFound, "missing")) {
		t.Error("NotFound status must be detected")
	}
	if isGCPNotFound(status.Error(codes.PermissionDenied, "denied")) {
		t.Error("PermissionDenied must not be not-found")
	}
}

func TestGCPSMFactory_MissingProject(t *testing.T) {
	t.Parallel()
	_, err := gcpSMFactory(context.Background(), backend.BackendConfig{
		Settings: map[string]any{},
	})
	if err == nil {
		t.Error("factory without project_id must fail")
	}
}

func TestClose_NilClient(t *testing.T) {
	t.Parallel()
	b := &GCPSecretManagerBackend{}
	if err := b.Close(); err != nil {
		t.Errorf("Close with nil client: %v", err)
	}
}
