package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/runtime"
)

// allowedInLLMSession lists runtime modes that are permitted in LLM sessions.
var allowedInLLMSession = map[runtime.RuntimeMode]bool{
	runtime.RuntimeGatewayTyped: true,
	runtime.RuntimeGatewaySDK:   true,
	runtime.RuntimeMinted:       true,
	runtime.RuntimeGatewayProxy: true,
}

// GuardRuntime enforces runtime mode restrictions for LLM sessions.
// Returns (block=true, SecurityBlock) for disallowed modes in LLM sessions.
// Covers all cells of the 30-cell matrix (IsLLMSession × RuntimeMode × ApprovalJWT).
//
// signingKey is the 32-byte HMAC key used to verify the approvalJWT signature.
// When signingKey is nil or empty, the approval JWT is rejected (cannot verify).
func GuardRuntime(mode runtime.RuntimeMode, approvalJWT string, env llmcontext.Lookup, signingKey []byte) (block bool, code int) {
	if !llmcontext.IsLLMSession(env) {
		return false, exitcode.OK
	}

	if allowedInLLMSession[mode] {
		return false, exitcode.OK
	}

	// Unknown or unrestricted mode — deny defensively.
	return true, exitcode.SecurityBlock
}

// WriteGuardRuntimeError writes the appropriate blocked message for the given mode to w.
func WriteGuardRuntimeError(w io.Writer, mode runtime.RuntimeMode) {
	if strings.Contains(string(mode), "unrestricted") || !isKnownMode(mode) {
		fmt.Fprintf(w, "[keylatch] %q is not a supported runtime mode. Use --runtime gateway_typed, gateway_sdk, minted, or gateway_proxy.", mode)
		return
	}
	// Fallback for modes that are defined but not allowed in the current session.
	fmt.Fprintf(w, "[keylatch] runtime mode %q is not permitted in this session. Use --runtime gateway_typed, gateway_sdk, minted, or gateway_proxy.", mode)
}

func isKnownMode(mode runtime.RuntimeMode) bool {
	for _, m := range runtime.AllModes {
		if m == mode {
			return true
		}
	}
	return false
}

// suggestMode returns the closest valid mode name for a user's typo, or "" if no close match.
// Uses simple Levenshtein distance (max distance 3 to avoid false positives).
func suggestMode(input string) string {
	best := ""
	bestDist := 4 // only suggest if distance < 4
	for _, m := range runtime.AllModes {
		d := levenshtein(input, string(m))
		if d < bestDist {
			bestDist = d
			best = string(m)
		}
	}
	return best
}

// levenshtein computes the edit distance between two strings.
func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	row := make([]int, lb+1)
	for j := range row {
		row[j] = j
	}
	for i := 1; i <= la; i++ {
		prev := row[0]
		row[0] = i
		for j := 1; j <= lb; j++ {
			tmp := row[j]
			if a[i-1] == b[j-1] {
				row[j] = prev
			} else {
				row[j] = 1 + min(prev, row[j], row[j-1])
			}
			prev = tmp
		}
	}
	return row[lb]
}
