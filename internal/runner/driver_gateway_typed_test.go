package runner_test

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// childTokenMaxUses mirrors the cap applied to gateway child tokens.
const childTokenMaxUses = 10000

type childTokenDriver struct {
	name string
	new  func(srv runner.GatewayServerStarter, key []byte, store string) runner.Driver
}

var childTokenDrivers = []childTokenDriver{
	{"typed", runner.NewGatewayTypedDriver},
	{"sdk", runner.NewGatewaySDKDriver},
}

// runChildToken runs command through a driver and returns the single minted token.
func runChildToken(t *testing.T, newDriver func(runner.GatewayServerStarter, []byte, string) runner.Driver, command []string) (token.Token, error) {
	t.Helper()
	store := filepath.Join(t.TempDir(), "tokens.json")
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	d := newDriver(&mockGatewayServer{addr: "127.0.0.1:17880", running: true}, key, store)
	_, runErr := d.Run(context.Background(), runner.ExecRequest{
		ConnectionSlug: "openai",
		Capability:     "chat_completion",
		Command:        command,
		Stdout:         &strings.Builder{},
		Stderr:         &strings.Builder{},
	}, sdkTmpl())

	records, err := token.List(token.ListOpts{IncludeRevoked: true}, store)
	require.NoError(t, err)
	require.Len(t, records, 1)
	return records[0], runErr
}

func TestGatewayChildToken_HumanChildIsBoundedAndRevoked(t *testing.T) {
	for _, drv := range childTokenDrivers {
		t.Run(drv.name, func(t *testing.T) {
			testutil.ClearLLMSessionEnv(t)
			tok, err := runChildToken(t, drv.new, []string{"sh", "-c", "exit 0"})
			require.NoError(t, err)
			assert.False(t, tok.LLMSession)
			assert.Equal(t, childTokenMaxUses, tok.MaxUses)
			assert.True(t, tok.Revoked)
		})
	}
}

func TestGatewayChildToken_AgentSessionIsMarked(t *testing.T) {
	for _, drv := range childTokenDrivers {
		t.Run(drv.name, func(t *testing.T) {
			testutil.ClearLLMSessionEnv(t)
			t.Setenv("CREDENTIALS_LLM_SESSION", "1")
			tok, err := runChildToken(t, drv.new, []string{"sh", "-c", "exit 0"})
			require.NoError(t, err)
			assert.True(t, tok.LLMSession)
		})
	}
}

func TestGatewayChildToken_RevokedAfterNonZeroExit(t *testing.T) {
	for _, drv := range childTokenDrivers {
		t.Run(drv.name, func(t *testing.T) {
			testutil.ClearLLMSessionEnv(t)
			tok, err := runChildToken(t, drv.new, []string{"sh", "-c", "exit 3"})
			require.NoError(t, err)
			assert.True(t, tok.Revoked)
		})
	}
}

func TestGatewayChildToken_RevokedWhenExecFails(t *testing.T) {
	for _, drv := range childTokenDrivers {
		t.Run(drv.name, func(t *testing.T) {
			testutil.ClearLLMSessionEnv(t)
			tok, err := runChildToken(t, drv.new, []string{"/nonexistent/bin"})
			require.Error(t, err)
			assert.True(t, tok.Revoked)
		})
	}
}

func TestGatewayChildToken_HarnessExecutableIsMarked(t *testing.T) {
	for _, drv := range childTokenDrivers {
		t.Run(drv.name, func(t *testing.T) {
			testutil.ClearLLMSessionEnv(t)
			script := filepath.Join(t.TempDir(), "claude")
			require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755))
			tok, err := runChildToken(t, drv.new, []string{script})
			require.NoError(t, err)
			assert.True(t, tok.LLMSession)
		})
	}
}
