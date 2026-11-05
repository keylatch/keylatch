package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/presence/presencetest"
)

const importYAML = `
schema_version: 2
defaults:
  caller:
    agent: { tiers: [D1, D2, D3, D4], approval: auto_if_contained }
connections:
  stripe:
    hosts: ["api.stripe.com"]
    egress: { allow: [registry.npmjs.org, evil.example] }
    callers:
      agent: { tiers: [D3, D5], approval: ask }
`

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func TestPolicyImportCompilesAYAMLFile(t *testing.T) {
	policyTestDir(t)
	seen := presencetest.Record(t)
	out, err := runCLI(t, "policy", "import", writeFile(t, "policy.yaml", importYAML))
	require.NoError(t, err, out)
	assert.Contains(t, out, "+ stripe:")
	assert.Contains(t, out, "tiers=D3,D5")
	require.Len(t, *seen, 1)
	assert.Contains(t, (*seen)[0], "approval=ask", "the approved summary shows the approval")

	docs := storeDocs(t)
	require.Contains(t, docs, "stripe")
	assert.Equal(t, []string{"api.stripe.com"}, docs["stripe"].Hosts)
}

func TestPolicyImportRefusesABadYAMLFileWithoutChangingAnything(t *testing.T) {
	policyTestDir(t)
	presencetest.Approve(t)
	_, err := runCLI(t, "policy", "import", writeFile(t, "policy.yaml", "schema_version: 2\nconnections:\n  a:\n    secret: op://x\n"))
	requireExitCode(t, err, exitcode.UserError)
	assert.Contains(t, err.Error(), "bindings belong")
	assert.Empty(t, storeDocs(t))
	_, err = runCLI(t, "policy", "import", filepath.Join(t.TempDir(), "missing.yaml"))
	requireExitCode(t, err, exitcode.UserError)
	_, err = runCLI(t, "policy", "import")
	requireExitCode(t, err, exitcode.UserError)
	_, err = runCLI(t, "policy", "import", t.TempDir(), "--from", "codex")
	requireExitCode(t, err, exitcode.UserError)
}

func TestPolicyImportDryRunShowsTheDiffAndAsksNobody(t *testing.T) {
	policyTestDir(t)
	seen := presencetest.Record(t)
	out, err := runCLI(t, "policy", "import", "--dry-run", writeFile(t, "policy.yaml", importYAML))
	require.NoError(t, err)
	assert.Contains(t, out, "+ stripe:")
	assert.Empty(t, *seen)
	assert.Empty(t, storeDocs(t))
}

func TestPolicyImportFromAHostBoundsTheStoredPolicy(t *testing.T) {
	policyTestDir(t)
	seen := presencetest.Record(t)
	_, err := runCLI(t, "policy", "import", writeFile(t, "policy.yaml", importYAML))
	require.NoError(t, err)
	*seen = nil

	settings := writeFile(t, "settings.json", `{"sandbox": {"network": {"allowedDomains": ["registry.npmjs.org", "api.stripe.com"]}, "filesystem": {"denyRead": ["~/.ssh/**"]}}}`)
	out, err := runCLI(t, "policy", "import", "--from", "claude-code", "--settings", settings)
	require.NoError(t, err, out)
	assert.Contains(t, out, "host=claude-code")
	require.Len(t, *seen, 1)
	assert.Contains(t, (*seen)[0], "bounded by the claude-code sandbox settings")

	doc := storeDocs(t)["stripe"]
	require.NotNil(t, doc.Host)
	assert.True(t, doc.Host.EgressRestricted)
	assert.ElementsMatch(t, []string{"registry.npmjs.org"}, doc.EffectiveEgress(), "evil.example was never on the host's list")
	assert.Contains(t, doc.EffectiveDeny(), "~/.ssh")
	assert.Equal(t, []string{"D3", "D5"}, doc.Callers[callerkind.Agent].Tiers, "an import changes no tier and no approval")
	assert.Equal(t, "ask", doc.Callers[callerkind.Agent].Approval)

	// Running it again is a no-op.
	*seen = nil
	out, err = runCLI(t, "policy", "import", "--from", "claude-code", "--settings", settings)
	require.NoError(t, err)
	assert.Contains(t, out, "no changes")
	assert.Empty(t, *seen)
}

func TestPolicyImportFromAHostLimitsItsConnections(t *testing.T) {
	policyTestDir(t)
	presencetest.Approve(t)
	_, err := runCLI(t, "policy", "import", writeExampleDir(t))
	require.NoError(t, err)
	settings := writeFile(t, "settings.json", `{"sandbox": {"network": {"allowedDomains": []}}}`)
	_, err = runCLI(t, "policy", "import", "--from", "claude-code", "--settings", settings, "--connection", "stripe")
	require.NoError(t, err)
	docs := storeDocs(t)
	assert.NotNil(t, docs["stripe"].Host)
	assert.Nil(t, docs["vercel"].Host)
	_, err = runCLI(t, "policy", "import", "--from", "claude-code", "--settings", settings, "--connection", "nope")
	requireExitCode(t, err, exitcode.UserError)
}

func TestPolicyImportFromAHostRefusesAnExcludedKeylatch(t *testing.T) {
	policyTestDir(t)
	presencetest.Approve(t)
	_, err := runCLI(t, "policy", "import", writeExampleDir(t))
	require.NoError(t, err)
	before := storeDocs(t)

	for _, excluded := range []string{`"keylatch run:*"`, `"bash:*"`, `"git push:*", "env:*"`} {
		settings := writeFile(t, "settings.json", `{"sandbox": {"excludedCommands": [`+excluded+`], "network": {"allowedDomains": []}}}`)
		_, err = runCLI(t, "policy", "import", "--from", "claude-code", "--settings", settings)
		requireExitCode(t, err, exitcode.PolicyDeny)
		assert.Contains(t, err.Error(), "host.sandbox.keylatch_excluded")
		assert.Contains(t, err.Error(), "outside its sandbox")
	}
	assert.Equal(t, len(before), len(storeDocs(t)))
	for name, d := range storeDocs(t) {
		assert.Nil(t, d.Host, name)
	}
}

func TestPolicyImportFromAHostNeedsAPolicyAndSettings(t *testing.T) {
	policyTestDir(t)
	presencetest.Approve(t)
	settings := writeFile(t, "settings.json", `{}`)
	_, err := runCLI(t, "policy", "import", "--from", "codex", "--settings", writeFile(t, "config.toml", "sandbox_mode = \"read-only\"\n"))
	requireExitCode(t, err, exitcode.UserError)
	assert.Contains(t, err.Error(), "no connection policy to bound")

	_, err = runCLI(t, "policy", "import", "--from", "vim", "--settings", settings)
	requireExitCode(t, err, exitcode.UserError)
	assert.True(t, strings.Contains(err.Error(), "unknown host"))
	t.Setenv("HOME", t.TempDir())
	_, err = runCLI(t, "policy", "import", "--from", "claude-code")
	requireExitCode(t, err, exitcode.UserError)
	assert.Contains(t, err.Error(), "--settings")
}
