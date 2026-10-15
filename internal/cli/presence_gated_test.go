package cli

import (
	"context"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/presence/presencetest"
	"github.com/keylatch/keylatch/internal/testutil"
)

func runGatewayUp(t *testing.T, args ...string) error {
	t.Helper()
	cmd := newGatewayUpCmd()
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetContext(context.Background())
	return cmd.Execute()
}

// Starting the gateway without an audit log needs a human; a refusal leaves
// nothing listening.
func TestGatewayUpNoAuditNeedsPresence(t *testing.T) {
	testutil.SetupHermeticConfig(t)
	testutil.ClearLLMSessionEnv(t)
	addr := freeLoopbackAddr(t)
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("declined", func(t *testing.T) {
		presencetest.Decline(t)
		assertSecurityBlock(t, runGatewayUp(t, "--no-audit", "--port", port))
	})
	t.Run("no terminal", func(t *testing.T) {
		presencetest.NoTerminal(t)
		assertSecurityBlock(t, runGatewayUp(t, "--no-audit", "--port", port))
	})
	t.Run("detached", func(t *testing.T) {
		presencetest.Approve(t)
		err := runGatewayUp(t, "--no-audit", "--detach", "--port", port)
		if err == nil || !strings.Contains(err.Error(), "--detach") {
			t.Fatalf("error = %v, want a refusal naming --detach", err)
		}
	})

	if conn, err := net.Dial("tcp", addr); err == nil {
		_ = conn.Close()
		t.Fatal("gateway is listening although --no-audit was refused")
	}
}

// A declined login stores nothing and never prompts for the credential.
func TestBackendLoginDeclinedStoresNothing(t *testing.T) {
	testutil.SetupHermeticConfig(t)
	testutil.SetupTestKeyring(t)
	testutil.ClearLLMSessionEnv(t)
	withInteractiveStdin(t, true)
	presencetest.Decline(t)

	prev := promptHiddenFn
	promptHiddenFn = func() ([]byte, error) {
		t.Error("the credential was prompted for after presence was declined")
		return nil, nil
	}
	t.Cleanup(func() { promptHiddenFn = prev })

	assertSecurityBlock(t, runBackendLogin(t, "vault"))
	if _, err := os.Stat(credentialDir(t)); !os.IsNotExist(err) {
		t.Fatalf("a declined login wrote a credential: %v", err)
	}
}
