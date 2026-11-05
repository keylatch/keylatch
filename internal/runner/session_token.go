package runner

import (
	"log/slog"
	"time"

	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/registry"
)

// sessionMaxUses bounds the requests one session token can authorise.
const sessionMaxUses = 1000

// sessionToken mints the token a child uses against the gateway. It is bound
// to the caller's classification, limited to the capabilities the template
// declares, and short-lived; revoke must run when the child exits.
func sessionToken(key []byte, store, actor string, caller callerkind.Kind, caps []string, ttl time.Duration) (jwt string, revoke func(), err error) {
	if caller == "" {
		caller = callerkind.Local(llmcontext.DefaultLookup, false).Kind
	}
	jwt, tok, err := token.Mint(token.TokenSpec{
		Actor:        actor,
		Capabilities: caps,
		TTL:          ttl,
		MaxUses:      sessionMaxUses,
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
