package runner_test

import (
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/runner"
)

// TestRedact_OpenAIKey verifies that OpenAI API key shapes are redacted.
func TestRedact_OpenAIKey(t *testing.T) {
	t.Parallel()
	input := `{"api_key":"sk-AbCdEfGhIjKlMnOpQrStUvWx"}`
	out := string(runner.Redact([]byte(input)))
	if strings.Contains(out, "sk-AbCdEfGhIjKlMnOpQrStUvWx") {
		t.Errorf("openai key not redacted: %s", out)
	}
	if !strings.Contains(out, "[REDACTED:openai-key]") {
		t.Errorf("expected [REDACTED:openai-key] in output: %s", out)
	}
}

// TestRedact_AnthropicKey verifies that Anthropic API key shapes are redacted.
func TestRedact_AnthropicKey(t *testing.T) {
	t.Parallel()
	input := `authorization: sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz012345`
	out := string(runner.Redact([]byte(input)))
	if strings.Contains(out, "sk-ant-api03-") {
		t.Errorf("anthropic key not redacted: %s", out)
	}
	if !strings.Contains(out, "[REDACTED:anthropic-key]") {
		t.Errorf("expected [REDACTED:anthropic-key] in output: %s", out)
	}
}

// TestRedact_StripeKey verifies that Stripe live/test key shapes are redacted.
func TestRedact_StripeKey(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input string
	}{
		{"live", `{"key":"sk_live_AbCdEfGhIjKlMnOpQrStUv"}`},
		{"test", `{"key":"sk_test_AbCdEfGhIjKlMnOpQrStUv"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out := string(runner.Redact([]byte(tc.input)))
			if strings.Contains(out, "sk_live_") || strings.Contains(out, "sk_test_") {
				t.Errorf("stripe key not redacted: %s", out)
			}
			if !strings.Contains(out, "[REDACTED:stripe-key]") {
				t.Errorf("expected [REDACTED:stripe-key] in output: %s", out)
			}
		})
	}
}

// TestRedact_BearerToken verifies that Bearer token header values are redacted.
func TestRedact_BearerToken(t *testing.T) {
	t.Parallel()
	input := `Authorization: Bearer eyJhbGciOiJIUzI1NiJ9`
	out := string(runner.Redact([]byte(input)))
	// The bearer-token pattern should match the whole "Bearer <token>" segment.
	if strings.Contains(out, "eyJhbGciOiJIUzI1NiJ9") {
		t.Errorf("bearer token not redacted: %s", out)
	}
}

// TestRedact_JWT verifies that JWT-shaped strings (three base64url segments) are redacted.
func TestRedact_JWT(t *testing.T) {
	t.Parallel()
	// Minimal valid JWT shape: three base64url-encoded segments.
	input := `token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ`
	out := string(runner.Redact([]byte(input)))
	if strings.Contains(out, "eyJhbGciOiJIUzI1NiJ9") {
		t.Errorf("JWT not redacted: %s", out)
	}
	if !strings.Contains(out, "[REDACTED:jwt]") {
		t.Errorf("expected [REDACTED:jwt] in output: %s", out)
	}
}

// TestRedact_NoMatch verifies that clean input is returned unchanged.
func TestRedact_NoMatch(t *testing.T) {
	t.Parallel()
	input := `{"data":["gpt-4","gpt-3.5-turbo"],"object":"list"}`
	out := runner.Redact([]byte(input))
	if string(out) != input {
		t.Errorf("clean input was modified: got %q, want %q", out, input)
	}
}

// TestRedact_BinarySafe verifies that non-UTF-8 bytes that do not match any
// pattern are passed through unchanged.
func TestRedact_BinarySafe(t *testing.T) {
	t.Parallel()
	// Bytes that are not valid UTF-8 and do not match any pattern.
	input := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}
	out := runner.Redact(input)
	if len(out) != len(input) {
		t.Errorf("binary-safe: length changed from %d to %d", len(input), len(out))
	}
	for i, b := range out {
		if b != input[i] {
			t.Errorf("binary-safe: byte %d changed from %#x to %#x", i, input[i], b)
		}
	}
}

// TestRedact_Boundary verifies that patterns at the start and end of the body
// are correctly redacted.
func TestRedact_Boundary(t *testing.T) {
	t.Parallel()

	// Pattern at start.
	startInput := `sk-AbCdEfGhIjKlMnOpQrStUv: extra text`
	startOut := string(runner.Redact([]byte(startInput)))
	if strings.Contains(startOut, "sk-AbCdEfGhIjKlMnOpQrStUv") {
		t.Errorf("pattern at start not redacted: %s", startOut)
	}

	// Pattern at end.
	endInput := `extra text: sk-AbCdEfGhIjKlMnOpQrStUv`
	endOut := string(runner.Redact([]byte(endInput)))
	if strings.Contains(endOut, "sk-AbCdEfGhIjKlMnOpQrStUv") {
		t.Errorf("pattern at end not redacted: %s", endOut)
	}
}

// FuzzRedact asserts that Redact never panics on arbitrary input.
func FuzzRedact(f *testing.F) {
	// Seed corpus with known inputs.
	f.Add([]byte(`sk-AbCdEfGhIjKlMnOpQrStUvWx`))
	f.Add([]byte(`Bearer eyJhbGciOiJIUzI1NiJ9`))
	f.Add([]byte(`{"data":[]}`))
	f.Add([]byte{0x00, 0xFF, 0xFE})
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic.
		_ = runner.Redact(data)
	})
}
