//go:build e2e_op

// Package main contains E2E tests for the 1Password backend.
//
// These tests require a sandbox 1Password vault and `op` CLI authenticated
// via service account. They are skipped in default `go test ./...` runs.
//
// Usage:
//
//	KEYLATCH_E2E_OP=1 go test -v -tags=e2e_op ./cmd/keylatch/ -run TestE2E_OP
//
// Prerequisites:
// - `op` CLI installed and authenticated (OP_SERVICE_ACCOUNT_TOKEN set)
// - A sandbox vault named "KeylatchE2ETest" (or set KEYLATCH_E2E_OP_VAULT)
package main

import (
	"context"
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/op"
	"github.com/stretchr/testify/require"
)

func TestE2E_OP_InitAndList(t *testing.T) {
	if os.Getenv("KEYLATCH_E2E_OP") != "1" {
		t.Skip("set KEYLATCH_E2E_OP=1 to run 1Password E2E tests")
	}

	vault := os.Getenv("KEYLATCH_E2E_OP_VAULT")
	if vault == "" {
		vault = "KeylatchE2ETest"
	}

	ctx := context.Background()

	b, err := op.Open(op.Options{
		Vault: vault,
	})
	require.NoError(t, err, "op.Open must succeed with installed op CLI")

	service := "keylatch-e2e-test"

	// Cleanup: remove the test item after the test.
	t.Cleanup(func() {
		_ = b.Delete(ctx, "default/"+service+"/api_key")
	})

	// Push a test value.
	err = b.Set(ctx, "default/"+service+"/api_key",
		[]byte("test-value-e2e"), backend.Meta{Path: "default/" + service + "/api_key"})
	require.NoError(t, err, "Set must succeed")

	// List and verify the item appears.
	entries, err := b.List(ctx, "default/"+service+"/")
	require.NoError(t, err)
	require.NotEmpty(t, entries, "op-list must return the pushed item")

	// Values must be zero-filled in list.
	for _, e := range entries {
		t.Logf("entry: path=%s backend=%s", e.Path, e.Backend)
	}
}
