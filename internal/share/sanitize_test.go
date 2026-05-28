package share_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/share"
)

func TestSanitize_NoCredentialLeak(t *testing.T) {
	// Build a receipt that contains a sensitive value in a field that
	// must never appear in the sanitized output. PolicyDecision and
	// CredentialShape are the fields most likely to carry policy-decision
	// raw values; we plant a fake credential string in both to be sure.
	const sensitiveValue = "sk-SUPERSECRET-CREDENTIAL-9999"

	receipt := runner.RuntimeReceipt{
		Runtime:         "direct_classic",
		Provider:        "openrouter",
		Capability:      "inject",
		PolicyDecision:  sensitiveValue, // must not appear in sanitized output
		CredentialShape: sensitiveValue, // must not appear in sanitized output
		ExitCode:        0,
	}

	sanitized := share.Sanitize(receipt)

	// Marshal to JSON to confirm no credential bytes surface.
	b, err := json.Marshal(sanitized)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	output := string(b)

	if strings.Contains(output, sensitiveValue) {
		t.Errorf("sanitized output contains credential value %q: %s", sensitiveValue, output)
	}

	// Assert required fields are present.
	if !strings.Contains(output, `"provider_name"`) {
		t.Errorf("expected provider_name in output, got: %s", output)
	}
	if !strings.Contains(output, `"runtime_mode"`) {
		t.Errorf("expected runtime_mode in output, got: %s", output)
	}
	if !strings.Contains(output, `"exit_code_class"`) {
		t.Errorf("expected exit_code_class in output, got: %s", output)
	}
}

func TestSanitize_ExitCodeClass(t *testing.T) {
	cases := []struct {
		exitCode int
		want     string
	}{
		{0, "success"},
		{1, "failure"},
		{127, "failure"},
		{-1, "error"},
	}
	for _, tc := range cases {
		r := runner.RuntimeReceipt{ExitCode: tc.exitCode}
		got := share.Sanitize(r)
		if got.ExitCodeClass != tc.want {
			t.Errorf("exitCode=%d: want %q, got %q", tc.exitCode, tc.want, got.ExitCodeClass)
		}
	}
}

func TestSanitize_ProviderAndRuntime(t *testing.T) {
	r := runner.RuntimeReceipt{
		Runtime:  "gateway_typed",
		Provider: "anthropic",
	}
	got := share.Sanitize(r)
	if got.ProviderName != "anthropic" {
		t.Errorf("expected ProviderName=anthropic, got %q", got.ProviderName)
	}
	if got.RuntimeMode != "gateway_typed" {
		t.Errorf("expected RuntimeMode=gateway_typed, got %q", got.RuntimeMode)
	}
}
