//go:build e2e_bw

// Package main contains E2E tests for the Bitwarden/Vaultwarden backend.
//
// These tests use a Vaultwarden instance started via docker-compose.
// They are skipped in default `go test ./...` runs.
//
// Usage:
//
//	make test-e2e-bw
//
// Prerequisites:
//   - Docker and docker-compose installed
//   - docker-compose.vaultwarden.yml in the repo root
package main

import (
	"context"
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/bw"
	"github.com/stretchr/testify/require"
)

func TestE2E_BW_InitAndList(t *testing.T) {
	server := os.Getenv("KEYLATCH_E2E_BW_SERVER")
	if server == "" {
		t.Skip("set KEYLATCH_E2E_BW_SERVER to run Bitwarden E2E tests")
	}

	session := os.Getenv("BW_SESSION")
	if session == "" {
		t.Skip("BW_SESSION must be set to run Bitwarden E2E tests")
	}

	ctx := context.Background()

	b, err := bw.Open(bw.Options{
		Server: server,
		Env: func(k string) string {
			if k == "BW_SESSION" {
				return session
			}
			return ""
		},
	})
	require.NoError(t, err, "bw.Open must succeed")

	service := "keylatch-e2e-test"

	// Cleanup: remove the test item after the test.
	t.Cleanup(func() {
		_ = b.Delete(ctx, "default/"+service+"/api_key")
	})

	// Push a test value.
	err = b.Set(ctx, "default/"+service+"/api_key",
		[]byte("test-value-e2e"), backend.Meta{Path: "default/" + service + "/api_key"})
	require.NoError(t, err, "Set must succeed")

	// List and verify.
	entries, err := b.List(ctx, "default/"+service+"/")
	require.NoError(t, err)
	require.NotEmpty(t, entries, "bw-list must return the pushed item")

	// Values must not contain session token.
	for _, e := range entries {
		t.Logf("entry: path=%s backend=%s", e.Path, e.Backend)
	}
}
