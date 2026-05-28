package cli

import (
	"bytes"
	"strings"
	"testing"
)

// TestAllowCmd_Suggest_KnownAgent verifies that --suggest <agent> prints the expected slugs.
func TestAllowCmd_Suggest_KnownAgent(t *testing.T) {
	cases := []struct {
		agent     string
		wantSlugs []string
	}{
		{"claude", []string{"anthropic", "openrouter"}},
		{"aider", []string{"openai", "anthropic"}},
		{"cursor-agent", []string{"openai", "anthropic"}},
		{"copilot-agent", []string{"openai"}},
		{"gemini", []string{"google-ai"}},
	}

	for _, tc := range cases {
		t.Run(tc.agent, func(t *testing.T) {
			cmd := newAllowCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)

			// Set the --suggest flag directly via the flag set.
			if err := cmd.Flags().Set("suggest", tc.agent); err != nil {
				t.Fatalf("failed to set --suggest flag: %v", err)
			}

			if err := cmd.RunE(cmd, nil); err != nil {
				t.Fatalf("RunE error: %v", err)
			}

			output := out.String()
			for _, slug := range tc.wantSlugs {
				if !strings.Contains(output, slug) {
					t.Errorf("output for agent %q missing slug %q\nfull output: %s", tc.agent, slug, output)
				}
			}
			// Should also contain a keylatch run ... --allow example.
			if !strings.Contains(output, "keylatch run") {
				t.Errorf("output for agent %q missing 'keylatch run' example\nfull output: %s", tc.agent, output)
			}
		})
	}
}

// TestAllowCmd_Suggest_UnknownAgent verifies that an unknown agent does not crash
// and prints helpful output (list of known agents).
func TestAllowCmd_Suggest_UnknownAgent(t *testing.T) {
	cmd := newAllowCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.Flags().Set("suggest", "unknown-agent-xyz"); err != nil {
		t.Fatalf("failed to set --suggest flag: %v", err)
	}

	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("RunE error: %v", err)
	}

	// Should mention it could not find the agent.
	combined := out.String()
	if !strings.Contains(combined, "unknown-agent-xyz") {
		t.Errorf("output should mention the unknown agent; got: %s", combined)
	}
}

// TestAllowCmd_NoFlag verifies that running without --suggest lists all known agents.
func TestAllowCmd_NoFlag(t *testing.T) {
	cmd := newAllowCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("RunE error: %v", err)
	}

	output := out.String()
	// Should list known agents.
	if !strings.Contains(output, "claude") {
		t.Errorf("no-flag output missing 'claude'; got: %s", output)
	}
}
