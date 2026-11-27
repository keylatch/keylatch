package cli

import (
	"net"
	"testing"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/presence/presencetest"
	"github.com/keylatch/keylatch/internal/testutil"
)

// Detection only ever tightens: with every agent signal absent, a privileged
// command still needs a human at a terminal, so an agent that hides itself
// gains nothing.
func TestPrivilegedNeedsPresenceWithoutDetection(t *testing.T) {
	testutil.SetupHermeticConfig(t)
	testutil.SetupTestKeyring(t)
	testutil.ClearLLMSessionEnv(t)
	if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
		t.Fatal("test precondition: no agent session may be detected")
	}
	withInteractiveStdin(t, true)
	dir, token := setupDecision(t)
	presencetest.NoTerminal(t)

	_, port, err := net.SplitHostPort(freeLoopbackAddr(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]func() error{
		"approve":       func() error { return decide(t, "approve", token) },
		"deny":          func() error { return decide(t, "deny", token) },
		"deny all":      func() error { return decide(t, "deny", "--all", "--yes") },
		"gateway up":    func() error { return runGatewayUp(t, "--no-audit", "--port", port) },
		"backend login": func() error { return runBackendLogin(t, "vault") },
	} {
		t.Run(name, func(t *testing.T) { assertSecurityBlock(t, run()) })
	}
	if got := statusOf(t, dir, token); got != "pending" {
		t.Fatalf("approval status = %q after refused decisions, want pending", got)
	}
}
