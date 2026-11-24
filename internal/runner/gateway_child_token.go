package runner

import (
	"log/slog"
	"time"

	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/harness"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// childTokenMaxUses bounds a leaked child token while leaving room for a long agent run (~2.8 calls/s over the 1h default TTL).
const childTokenMaxUses = 10000

// mintChildToken mints the gateway token handed to a child and returns the JWT
// with a function that revokes it once the child is done.
func mintChildToken(req ExecRequest, actor, capability string, ttl time.Duration, key []byte, storePath string) (string, func(), error) {
	jwtStr, tok, err := token.Mint(token.TokenSpec{
		Actor:        actor,
		Capabilities: []string{capability},
		TTL:          ttl,
		MaxUses:      childTokenMaxUses,
		LLMSession:   childIsAgent(req.Command),
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		return "", nil, err
	}
	revoke := func() {
		if err := token.Revoke(tok.ID, storePath); err != nil {
			slog.Warn("gateway child token revoke failed", "accessor", tok.Accessor)
		}
	}
	return jwtStr, revoke, nil
}

// childIsAgent reports whether the child is an agent: either the parent is in
// an agent session or the command is a known agent harness.
func childIsAgent(cmd []string) bool {
	if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
		return true
	}
	if len(cmd) == 0 {
		return false
	}
	_, ok := harness.ByExecutable(cmd[0])
	return ok
}
