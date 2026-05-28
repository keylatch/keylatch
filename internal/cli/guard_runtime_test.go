package cli_test

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keylatch/keylatch/internal/cli"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/runtime"
	"github.com/stretchr/testify/assert"
)

// makeTestSigningKey returns a fresh 32-byte random key.
func makeTestSigningKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return key
}

// makeValidApprovalJWT mints a real HS256 JWT with hardware root claims.
func makeValidApprovalJWT(t *testing.T, key []byte) string {
	t.Helper()
	claims := jwt.MapClaims{
		"exp":           time.Now().Add(5 * time.Minute).Unix(),
		"iat":           time.Now().Unix(),
		"apv_root_hmac": "deadbeefdeadbeef",
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	if err != nil {
		t.Fatalf("mint valid JWT: %v", err)
	}
	return tok
}

// makeInvalidApprovalJWT returns a JWT signed with a different key (signature fails).
func makeInvalidApprovalJWT(t *testing.T, key []byte) string {
	t.Helper()
	wrongKey := make([]byte, 32)
	_, _ = rand.Read(wrongKey)
	// ensure wrongKey != key
	wrongKey[0] ^= key[0] ^ 0xff
	claims := jwt.MapClaims{
		"exp":           time.Now().Add(5 * time.Minute).Unix(),
		"iat":           time.Now().Unix(),
		"apv_root_hmac": "deadbeef",
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(wrongKey)
	if err != nil {
		t.Fatalf("mint invalid JWT: %v", err)
	}
	return tok
}

// S0-15: 30-cell matrix test: IsLLMSession(2) × RuntimeMode(5) × ApprovalJWT(3) = 30 cells.
// RuntimeMode(5) = gateway_typed, gateway_sdk, direct_brokered, gateway_proxy,
// direct_classic_sandboxed (reinstated EPIC-24). direct_classic permanently removed.
const expectedCells = 2 * 5 * 3 // 30

func TestGuardRuntimeMatrix(t *testing.T) {
	t.Parallel()

	key := makeTestSigningKey(t)
	validJWT := makeValidApprovalJWT(t, key)
	invalidJWT := makeInvalidApprovalJWT(t, key)

	type cell struct {
		isLLM       bool
		mode        runtime.RuntimeMode
		approvalJWT string
		wantBlock   bool
		wantCode    int
	}

	// jwt values used for the matrix: valid, invalid, empty
	jwtCases := []string{validJWT, invalidJWT, ""}

	var cells []cell
	for _, isLLM := range []bool{true, false} {
		for _, mode := range runtime.AllModes {
			for _, jwtVal := range jwtCases {
				wantBlock := false
				wantCode := exitcode.OK

				if isLLM {
					switch mode {
					case runtime.RuntimeGatewayTyped,
						runtime.RuntimeGatewaySDK,
						runtime.RuntimeDirectBrokered,
						runtime.RuntimeGatewayProxy,
						runtime.RuntimeDirectClassicSandboxed:
						// All v1.0.0 modes (including reinstated direct_classic_sandboxed)
						// are permitted in LLM sessions. The OS sandbox provides isolation.
						wantBlock = false
					default:
						wantBlock = true
						wantCode = exitcode.SecurityBlock
					}
				}

				cells = append(cells, cell{isLLM, mode, jwtVal, wantBlock, wantCode})
			}
		}
	}

	assert.Len(t, cells, expectedCells, "matrix must have exactly %d cells", expectedCells)

	for _, c := range cells {
		c := c
		env := func(k string) string {
			if c.isLLM && k == "CLAUDE_CODE" {
				return "1"
			}
			return ""
		}
		t.Run("", func(t *testing.T) {
			t.Parallel()

			stderr := &bytes.Buffer{}
			block, code := cli.GuardRuntime(c.mode, c.approvalJWT, llmcontext.Lookup(env), key)

			assert.Equal(t, c.wantBlock, block, "mode=%s isLLM=%v jwt=%q", c.mode, c.isLLM, c.approvalJWT)
			assert.Equal(t, c.wantCode, code, "mode=%s isLLM=%v jwt=%q", c.mode, c.isLLM, c.approvalJWT)

			if block {
				cli.WriteGuardRuntimeError(stderr, c.mode)
				assert.NotEmpty(t, stderr.String(), "stderr must have message when blocked")
			}
		})
	}
}

func TestGuardRuntimeMatrix_NoOutputWhenAllowed(t *testing.T) {
	t.Parallel()
	key := makeTestSigningKey(t)
	env := func(k string) string {
		if k == "CLAUDE_CODE" {
			return "1"
		}
		return ""
	}

	for _, mode := range []runtime.RuntimeMode{
		runtime.RuntimeGatewayTyped,
		runtime.RuntimeGatewaySDK,
		runtime.RuntimeDirectBrokered,
		runtime.RuntimeGatewayProxy,
	} {
		block, code := cli.GuardRuntime(mode, "", llmcontext.Lookup(env), key)
		assert.False(t, block, "mode %s must be allowed in LLM session", mode)
		assert.Equal(t, exitcode.OK, code)
	}
}

// TestGuardRuntime_UnknownMode_SecurityBlock verifies that an unknown/removed mode
// is denied defensively in LLM sessions.
func TestGuardRuntime_UnknownMode_SecurityBlock(t *testing.T) {
	t.Parallel()

	key := makeTestSigningKey(t)
	llmEnv := llmcontext.Lookup(func(k string) string {
		if k == "CLAUDE_CODE" {
			return "1"
		}
		return ""
	})

	// An unknown mode string should be denied in LLM sessions.
	block, code := cli.GuardRuntime("unknown_mode_xyz", "", llmEnv, key)
	assert.True(t, block, "unknown mode must be denied in LLM session")
	assert.Equal(t, exitcode.SecurityBlock, code)
}
