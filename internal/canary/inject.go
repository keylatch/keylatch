package canary

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// BuildCanary returns a synthetic canary token with pattern
// klc-canary-<provider>-<random16hex>.
// The token value is not logged — only its metadata (provider, session_id) is
// emitted as an audit event.
func BuildCanary(provider string) (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("klc-canary-%s-%s", strings.ToLower(provider), hex.EncodeToString(b)), nil
}

// EnvVarName returns the environment variable name used to inject a canary
// token for the given provider.
// Example: "anthropic" → "KEYLATCH_CANARY_ANTHROPIC"
//
//	"open-ai"  → "KEYLATCH_CANARY_OPEN_AI"
func EnvVarName(provider string) string {
	slug := strings.ToUpper(strings.ReplaceAll(provider, "-", "_"))
	return fmt.Sprintf("KEYLATCH_CANARY_%s", slug)
}
