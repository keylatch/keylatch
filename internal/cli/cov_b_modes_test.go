package cli

// Coverage for modes_cmd.go. Hermetic: no network, no OS keychain.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestModesCmd_JSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"modes", "--json"})

	// Execute — may exit non-zero if gateway unavailable; that is correct behaviour.
	_ = root.Execute()

	output := strings.TrimSpace(out.String())
	if output == "" {
		t.Fatal("expected non-empty JSON output from modes --json")
	}

	// Modes JSON is wrapped: {"_schema": "v1", "modes": [...]}.
	var wrapper struct {
		Schema string      `json:"_schema"`
		Modes  []ModeEntry `json:"modes"`
	}
	if err := json.Unmarshal([]byte(output), &wrapper); err != nil {
		t.Fatalf("JSON parse error: %v — output: %s", err, output)
	}
	if len(wrapper.Modes) == 0 {
		t.Error("expected at least one mode entry")
	}
	for _, m := range wrapper.Modes {
		if strings.Contains(m.Name, "classic") {
			t.Errorf("mode %q was removed and must not be listed", m.Name)
		}
	}
}

func TestModesCmd_Text(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"modes"})

	_ = root.Execute()

	output := out.String()
	if !strings.Contains(output, "gateway_typed") {
		t.Errorf("expected 'gateway_typed' in modes output, got:\n%s", output)
	}
}
