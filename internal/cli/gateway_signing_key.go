package cli

import (
	"os"

	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

// LoadGatewaySigningKey unwraps the gateway signing key with the KEK that
// opens the keyring. A raw key file from an older install is wrapped and
// removed on the way. With create set a missing key is generated.
func LoadGatewaySigningKey(env llmcontext.Lookup, create bool) ([]byte, error) {
	kr, k, _, err := openKeyringAt(paths.ResolveKeyringPath(os.Getenv), !llmcontext.IsLLMSession(env))
	if err != nil {
		return nil, err
	}
	kr.Zero()
	return token.LoadSigningKey(env, k, create)
}
