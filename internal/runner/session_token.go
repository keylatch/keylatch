package runner

import (
	"log/slog"
	"time"

	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/harness"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/registry"
)

// sessionMaxUses bounds a leaked token while leaving room for a long agent run (~2.8 calls/s over the 1h default TTL).
const sessionMaxUses = 10000

// sessionToken mints the token a child uses against the gateway. It is bound
// to the caller's classification, limited to the capabilities the template
// declares, and short-lived; revoke must run when the child exits. The token
// is marked as an agent session when the caller or the child command is one.
func sessionToken(key []byte, store, actor string, caller callerkind.Kind, command []string, caps []string, ttl time.Duration) (jwt string, revoke func(), err error) {
	if caller == "" {
		caller = callerkind.Local(llmcontext.DefaultLookup, false).Kind
	}
	jwt, tok, err := token.Mint(token.TokenSpec{
		Actor:        actor,
		Capabilities: caps,
		TTL:          ttl,
		MaxUses:      sessionMaxUses,
		LLMSession:   childIsAgent(caller, command),
		Caller:       caller,
		SigningKey:   key,
		StorePath:    store,
	})
	if err != nil {
		return "", nil, err
	}
	return jwt, func() {
		if err := token.Revoke(tok.ID, store, key); err != nil {
			slog.Warn("could not revoke the session token", "error", err)
		}
	}, nil
}

func sessionCapabilities(tmpl registry.ConnectionTemplate, capability string) []string {
	if capability == "" || capability == "inject" {
		return tmpl.GatewayCapabilities()
	}
	return []string{tmpl.Provider + "." + capability}
}

// childIsAgent reports whether the child is an agent: either the caller is an
// agent or the command is a known agent harness.
func childIsAgent(caller callerkind.Kind, cmd []string) bool {
	if caller == callerkind.Agent {
		return true
	}
	if len(cmd) == 0 {
		return false
	}
	_, ok := harness.ByExecutable(cmd[0])
	return ok
}
