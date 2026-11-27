package hostimport

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/policy/connpolicy"
)

const claudeUser = `{
  "sandbox": {
    "enabled": true,
    "excludedCommands": ["docker:*", "git push:*"],
    "network": {"allowedDomains": ["registry.npmjs.org", "*.github.com", "github.com", "com", "api.stripe.com"]},
    "filesystem": {"allowWrite": ["~/.cache/pnpm", "//var/tmp/build", "relative/odd"], "denyRead": ["~/.ssh/**", "~/.aws"], "denyWrite": ["./.env"]}
  },
  "permissions": {"deny": ["Read(~/.gnupg/**)", "Edit(./secrets/**)", "Bash(rm:*)", "Read(//etc/shadow)"]}
}`

const claudeProject = `{"sandbox": {"network": {"allowedDomains": ["pypi.org"]}}}`

const codexConfig = `
model = "gpt-5"
sandbox_mode = "workspace-write"   # keep the work in the project

[sandbox_workspace_write]
writable_roots = [
  "/var/cache/build",
  "~/.cargo/registry",   # shared
]
network_access = false
`

func write(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func TestClaudeCodeSettingsBecomeBounds(t *testing.T) {
	b, err := Load(ClaudeCode, []string{write(t, "settings.json", claudeUser), write(t, "project.json", claudeProject)})
	require.NoError(t, err)
	assert.Equal(t, ClaudeCode, b.Source)
	assert.True(t, b.EgressRestricted)
	assert.ElementsMatch(t, []string{"*.github.com", "api.stripe.com", "github.com", "pypi.org", "registry.npmjs.org"}, b.EgressAllow)
	assert.True(t, b.WriteRestricted)
	assert.ElementsMatch(t, []string{"${project}", "~/.cache/pnpm", "/var/tmp/build"}, b.FSWrite)
	assert.ElementsMatch(t, []string{"~/.ssh", "~/.aws", "${project}/.env", "~/.gnupg", "${project}/secrets", "/etc/shadow"}, b.FSDeny)
	assert.ElementsMatch(t, []string{"docker:*", "git push:*"}, b.Excluded)
	joined := ""
	for _, w := range b.Warnings {
		joined += w + "\n"
	}
	assert.Contains(t, joined, `"com"`, "a public suffix is skipped with a reason")
	assert.Contains(t, joined, "relative/odd")
	assert.Len(t, b.Files, 2)
	assert.NoError(t, (connpolicy.Document{SchemaVersion: 2, Connection: "c"}).WithHost(b.HostBounds).Validate(), "the bounds are a valid policy fragment")
}

func TestClaudeCodeWithoutALimitSetsNoBound(t *testing.T) {
	b, err := Load(ClaudeCode, []string{write(t, "s.json", `{"sandbox": {"enabled": true}}`)})
	require.NoError(t, err)
	assert.False(t, b.EgressRestricted)
	assert.False(t, b.WriteRestricted)

	b, err = Load(ClaudeCode, []string{write(t, "s.json", `{"sandbox": {"network": {"allowedDomains": ["*"]}}}`)})
	require.NoError(t, err)
	assert.False(t, b.EgressRestricted, "a wildcard allows everything and so bounds nothing")

	b, err = Load(ClaudeCode, []string{write(t, "s.json", `{"sandbox": {"network": {"allowedDomains": []}}}`)})
	require.NoError(t, err)
	assert.True(t, b.EgressRestricted)
	assert.Empty(t, b.EgressAllow, "an empty list allows no domain")
}

func TestCodexConfigBecomesBounds(t *testing.T) {
	b, err := Load(Codex, []string{write(t, "config.toml", codexConfig)})
	require.NoError(t, err)
	assert.True(t, b.EgressRestricted)
	assert.Empty(t, b.EgressAllow, "network_access = false leaves no destination")
	assert.True(t, b.WriteRestricted)
	assert.ElementsMatch(t, []string{"${project}", "/var/cache/build", "~/.cargo/registry"}, b.FSWrite)

	b, err = Load(Codex, []string{write(t, "config.toml", "sandbox_mode = \"read-only\"\n")})
	require.NoError(t, err)
	assert.True(t, b.WriteRestricted)
	assert.Empty(t, b.FSWrite, "a read-only host writes nowhere")
	assert.True(t, b.EgressRestricted)

	b, err = Load(Codex, []string{write(t, "config.toml", "sandbox_mode = \"danger-full-access\"\n")})
	require.NoError(t, err)
	assert.False(t, b.WriteRestricted)
	assert.False(t, b.EgressRestricted)

	_, err = Load(Codex, []string{write(t, "config.toml", "[[arrays]]\n")})
	assert.ErrorIs(t, err, errTOML)
	_, err = Load(Codex, []string{write(t, "config.toml", "key value\n")})
	assert.Error(t, err)
}

func TestGeminiSettingsBecomeBounds(t *testing.T) {
	b, err := Load(Gemini, []string{write(t, "settings.json", `{
	  "excludedCommands": ["bash:*"],
	  "tools": {"sandbox": {"network": {"allowedDomains": ["registry.npmjs.org"]}, "excludedCommands": ["docker"]}}
	}`)})
	require.NoError(t, err)
	assert.True(t, b.EgressRestricted)
	assert.Equal(t, []string{"registry.npmjs.org"}, b.EgressAllow)
	assert.ElementsMatch(t, []string{"bash:*", "docker"}, b.Excluded)

	b, err = Load(Gemini, []string{write(t, "settings.json", `{"sandbox": true}`)})
	require.NoError(t, err)
	assert.False(t, b.EgressRestricted)
}

func TestLoadErrors(t *testing.T) {
	_, err := Load("vim", []string{"x"})
	assert.ErrorContains(t, err, "unknown host")
	_, err = Load(ClaudeCode, nil)
	assert.ErrorContains(t, err, "--settings")
	_, err = Load(ClaudeCode, []string{filepath.Join(t.TempDir(), "missing.json")})
	assert.Error(t, err)
	_, err = Load(ClaudeCode, []string{write(t, "bad.json", "{")})
	assert.ErrorContains(t, err, "not valid JSON")
	_, err = Load(Gemini, []string{write(t, "bad.json", "{")})
	assert.ErrorContains(t, err, "not valid JSON")
}

func TestLintExcludedFindsKeylatchAndWrappers(t *testing.T) {
	assert.Empty(t, LintExcluded([]string{"docker:*", "git push:*", "pnpm install:*", "/usr/bin/make"}))
	bad := LintExcluded([]string{
		"keylatch run:*", "keylatch", "/home/u/.local/bin/keylatch:*", "keylatchd:*", "keylatch-relay",
		"bash:*", "sh -c", "env:*", "xargs:*", "sudo:*", "python3:*", "/usr/bin/node:*", "*", "", ":*",
	})
	assert.Len(t, bad, 15, "%v", bad)
	for _, b := range bad {
		assert.Regexp(t, `\(.+\)$`, b, "each finding says why")
	}
}

func TestNormalizePath(t *testing.T) {
	for in, want := range map[string]string{
		"~/.ssh/**": "~/.ssh", "~/.aws": "~/.aws", "/etc/shadow": "/etc/shadow", "//var/tmp": "/var/tmp",
		"./secrets/*": "${project}/secrets", "./.env": "${project}/.env", ".": "${project}", "/opt/x/": "/opt/x", "~": "~",
	} {
		got, ok := normalizePath(in)
		assert.True(t, ok, in)
		assert.Equal(t, want, got, in)
	}
	for _, bad := range []string{"relative", "/a/../b", "/a/*/b", "", "~/x/../y"} {
		_, ok := normalizePath(bad)
		assert.False(t, ok, bad)
	}
}

func TestDefaultFilesListsWhatExists(t *testing.T) {
	home, dir := t.TempDir(), t.TempDir()
	assert.Empty(t, DefaultFiles(ClaudeCode, home, dir))
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".claude"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte("{}"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".claude"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".claude", "settings.local.json"), []byte("{}"), 0o600))
	files := DefaultFiles(ClaudeCode, home, dir)
	assert.Equal(t, []string{filepath.Join(home, ".claude", "settings.json"), filepath.Join(dir, ".claude", "settings.local.json")}, files)
	assert.Empty(t, DefaultFiles(Codex, home, dir))
	assert.Empty(t, DefaultFiles("vim", home, dir))
}

func TestDiffReportsWhatChangedSinceTheLastImport(t *testing.T) {
	last := connpolicy.HostBounds{EgressRestricted: true, EgressAllow: []string{"a.com", "b.com"}, FSDeny: []string{"~/.ssh"}}
	now := connpolicy.HostBounds{EgressRestricted: true, EgressAllow: []string{"b.com", "c.com"}, FSDeny: []string{"~/.ssh", "~/.aws"}, WriteRestricted: true, FSWrite: []string{"/w"}}
	assert.ElementsMatch(t, []string{
		"+ egress c.com", "- egress a.com", "+ deny ~/.aws", "+ write /w", "~ write_restricted false -> true",
	}, Diff(last, now))
	assert.Empty(t, Diff(last, last))
}

// The owner's settings narrow a policy and never widen it.
func TestImportingTheOwnersSettingsDoesNotWidenAPolicy(t *testing.T) {
	b, err := Load(ClaudeCode, []string{write(t, "settings.json", claudeUser)})
	require.NoError(t, err)
	doc := connpolicy.Document{
		SchemaVersion: 2, Connection: "stripe",
		Egress: &connpolicy.Egress{Allow: []string{"registry.npmjs.org", "evil.example", "api.stripe.com"}},
		FS:     &connpolicy.FS{Write: []string{"${project}"}, Deny: []string{"~/.kube"}},
		Callers: map[callerkind.Kind]connpolicy.CallerRule{
			callerkind.Agent: {Allow: true, Tiers: []string{"D3", "D5"}},
		},
	}
	bounded := doc.WithHost(b.HostBounds)
	before := doc.Decide(connpolicy.Request{Caller: callerkind.Agent, Tier: "D5"})
	after := bounded.Decide(connpolicy.Request{Caller: callerkind.Agent, Tier: "D5"})
	assert.ElementsMatch(t, []string{"registry.npmjs.org", "api.stripe.com"}, after.Egress, "evil.example was never on the host's list")
	assert.Contains(t, before.Egress, "evil.example")
	assert.ElementsMatch(t, []string{"~/.kube", "~/.ssh", "~/.aws", "${project}/.env", "~/.gnupg", "${project}/secrets", "/etc/shadow"}, after.FSDeny)
	assert.True(t, bounded.WriteAllowed("${project}", doc.FS.Write))
	assert.False(t, bounded.WriteAllowed("/home/u/other", []string{"/home/u/other"}))
	assert.Equal(t, before.Tiers, after.Tiers)
	assert.Equal(t, before.Approval, after.Approval)
}

func TestTOMLParserEdgeCases(t *testing.T) {
	root, err := parseTOML("a = 'literal # not a comment'\nb = \"quoted # also\" # real comment\nn = 42\n[t.u]\nlist = [\"x\", 'y', [\"nested\"]]\nflag = true\n")
	require.NoError(t, err)
	assert.Equal(t, "literal # not a comment", root["a"])
	assert.Equal(t, "quoted # also", root["b"])
	assert.EqualValues(t, 42, root["n"])
	u := root["t"].(map[string]any)["u"].(map[string]any)
	assert.Equal(t, []any{"x", "y", []any{"nested"}}, u["list"])
	assert.Equal(t, true, u["flag"])

	for _, bad := range []string{"[unterminated", "k = ", "k = @", "k = [1, 2", "k = \"unterminated"} {
		_, err := parseTOML(bad)
		assert.Error(t, err, bad)
	}
}
