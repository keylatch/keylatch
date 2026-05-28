package cli_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runHelpTopic executes `keylatch help-topic <topic>` via the real root command
// tree and returns the captured stdout output.
func runHelpTopic(t *testing.T, topic string) string {
	t.Helper()
	root := cli.NewRootCommand()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"help-topic", topic})
	err := root.ExecuteContext(context.Background())
	require.NoError(t, err, "help-topic %s must not return an error", topic)
	return buf.String()
}

// TestHelpTopicModes verifies the modes topic prints non-empty content.
func TestHelpTopicModes(t *testing.T) {
	out := runHelpTopic(t, "modes")
	assert.NotEmpty(t, out, "modes topic must produce output")
	assert.Contains(t, out, "gateway_typed", "modes output must include gateway_typed mode")
	assert.Contains(t, out, "direct_classic", "modes output must include direct_classic mode")
}

// TestHelpTopicBackends verifies the backends topic prints the capabilities matrix.
func TestHelpTopicBackends(t *testing.T) {
	out := runHelpTopic(t, "backends")
	assert.NotEmpty(t, out, "backends topic must produce output")
	assert.Contains(t, out, "keychain", "backends output must include keychain backend")
	assert.Contains(t, out, "file", "backends output must include file backend")
}

// TestHelpTopicProviders verifies the providers topic produces non-empty output.
// When the registry has no providers (test environment without bootstrap), it
// prints the "No providers registered" message — still non-empty.
func TestHelpTopicProviders(t *testing.T) {
	// Initialise registry so providers are available.
	registryTestSetup(t)

	out := runHelpTopic(t, "providers")
	assert.NotEmpty(t, out, "providers topic must produce output")
}

// TestHelpTopicSecurity verifies the security topic prints the six-point model.
func TestHelpTopicSecurity(t *testing.T) {
	out := runHelpTopic(t, "security")
	assert.NotEmpty(t, out, "security topic must produce output")
	assert.Contains(t, out, "LLM session detection", "security output must include LLM session detection")
	assert.Contains(t, out, "gateway", "security output must mention gateway isolation")
}

// TestHelpTopicErrors verifies the errors topic prints exit codes and KL ranges.
func TestHelpTopicErrors(t *testing.T) {
	out := runHelpTopic(t, "errors")
	assert.NotEmpty(t, out, "errors topic must produce output")
	assert.Contains(t, out, "SecurityBlock", "errors output must include SecurityBlock exit code")
	assert.Contains(t, out, "KL-0001", "errors output must include KL-0001 range")
	assert.Contains(t, out, "KL-0500", "errors output must include KL-0500 security range")
}

// TestHelpTopicWizard verifies the wizard topic prints the UI URL.
func TestHelpTopicWizard(t *testing.T) {
	out := runHelpTopic(t, "wizard")
	assert.NotEmpty(t, out, "wizard topic must produce output")
	assert.Contains(t, out, "127.0.0.1:7890", "wizard output must include the UI address")
}

// TestHelpTopicTroubleshooting verifies the troubleshooting topic prints top issues and error ranges.
func TestHelpTopicTroubleshooting(t *testing.T) {
	out := runHelpTopic(t, "troubleshooting")
	assert.NotEmpty(t, out, "troubleshooting topic must produce output")
	assert.Contains(t, out, "Daemon not running", "troubleshooting output must include daemon issue")
	assert.Contains(t, out, "Backend unavailable", "troubleshooting output must include backend issue")
	assert.Contains(t, out, "KL-0500", "troubleshooting output must include KL-0500 security range")
	assert.Contains(t, out, "keylatch doctor", "troubleshooting output must reference keylatch doctor")
}

// TestHelpTopicParentListsAllTopics verifies `keylatch help-topic` (no args) lists all 7 topics.
func TestHelpTopicParentListsAllTopics(t *testing.T) {
	root := cli.NewRootCommand()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"help-topic", "--help"})
	_ = root.ExecuteContext(context.Background())
	out := buf.String()

	topics := []string{"modes", "backends", "providers", "security", "errors", "wizard", "troubleshooting"}
	for _, topic := range topics {
		assert.Contains(t, out, topic, "help-topic --help must list topic %q", topic)
	}
}
