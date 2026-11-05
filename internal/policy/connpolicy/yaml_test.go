package connpolicy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/callerkind"
)

const yamlPolicyFile = `
schema_version: 2
defaults:
  caller:
    agent: { tiers: [D1, D2, D3, D4], approval: auto_if_contained, ttl: 15m, max_requests: 500 }
    host:  { tiers: [D1, D2, D3, D4], approval: auto_if_contained, ttl: 15m }
    human: { tiers: [D1, D2, D3, D4, D5, D6], approval: presence_for_D6 }
    service: deny
  egress:
    allow: [registry.npmjs.org]
    deny_private_ranges: true
  fs:
    write: ["${project}"]
    read:  ["${project}", "${toolchain_caches}"]
    deny:  ["${keylatch_state}", "~/.ssh", "~/.aws"]

connections:
  stripe-test:
    hosts: ["api.stripe.com:443", "files.stripe.com:443"]
    capabilities: ["*"]
    callers:
      agent: { tiers: [D2, D3], approval: auto }
  stripe-live:
    hosts: ["api.stripe.com:443"]
    callers:
      agent: { tiers: [D1, D3], approval: ask }
  app-local:
    fs:
      deny: ["~/.kube"]
    callers:
      agent: { tiers: [D1, D3], approval: auto }

commands:
  - match: ["/usr/bin/pnpm", "test", "**"]
    connections: [stripe-test, app-local]
    tiers: [D3, D4]
`

func TestParseYAMLCompilesOneDocumentPerConnection(t *testing.T) {
	docs, err := ParseYAML([]byte(yamlPolicyFile))
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"stripe-test", "stripe-live", "app-local"}, Connections(docs))

	test := docs["stripe-test"]
	assert.Equal(t, []string{"api.stripe.com:443", "files.stripe.com:443"}, test.Hosts)
	assert.Equal(t, []string{"*"}, test.Capabilities)
	assert.Equal(t, "ask", docs["stripe-live"].Decide(Request{Caller: callerkind.Agent, Tier: D3}).Approval)
	got := test.Decide(Request{Caller: callerkind.Agent, Tier: D3})
	assert.True(t, got.Allow)
	assert.Equal(t, "auto", got.Approval)
	assert.Equal(t, 0, got.MaxRequests, "the connection's agent entry replaces the default entry")
	assert.False(t, test.Decide(Request{Caller: callerkind.Agent, Tier: D4}).Allow, "D4 is not in the connection's tiers")

	assert.True(t, test.Decide(Request{Caller: callerkind.Human, Tier: D6}).Allow, "a kind the connection does not list takes the default entry")
	assert.False(t, test.Decide(Request{Caller: callerkind.Service, Tier: D2}).Allow, "the default entry may be a denial")

	assert.Equal(t, []string{"registry.npmjs.org"}, test.Decide(Request{Caller: callerkind.Agent, Tier: D3}).Egress, "egress comes from the defaults")
	assert.Equal(t, []string{"${keylatch_state}", "~/.aws", "~/.kube", "~/.ssh"}, docs["app-local"].Decide(Request{Caller: callerkind.Agent, Tier: D3}).FSDeny, "a connection adds to the default denies and never drops one")

	require.Len(t, test.Commands, 1)
	assert.Equal(t, []string{"/usr/bin/pnpm", "test", "**"}, test.Commands[0].Match)
	assert.Empty(t, docs["stripe-live"].Commands)
	pnpm := Request{Caller: callerkind.Agent, Command: []string{"pnpm", "test"}, Exe: "/usr/bin/pnpm", Tier: D2}
	assert.False(t, test.Decide(pnpm).Allow, "a pinned command is narrowed to its tiers")
}

func TestParseYAMLRefusesWhatItCannotCompile(t *testing.T) {
	for name, tc := range map[string]struct{ doc, why string }{
		"wrong version":        {"schema_version: 1\nconnections: {a: {}}\n", "schema_version"},
		"no connections":       {"schema_version: 2\n", "no connections"},
		"not yaml":             {"schema_version: [", "policy YAML"},
		"unknown top key":      {"schema_version: 2\nbogus: 1\nconnections: {a: {}}\n", "bogus"},
		"unknown field":        {"schema_version: 2\nconnections: {a: {bogus: 1}}\n", "bogus"},
		"secret is a binding":  {"schema_version: 2\nconnections:\n  a:\n    secret: op://x/y\n", "connections.a.secret"},
		"slots are bindings":   {"schema_version: 2\nconnections:\n  a:\n    slots: []\n", "bindings belong"},
		"adapter is a binding": {"schema_version: 2\nconnections:\n  a:\n    adapter: postgres\n", "connections.a.adapter"},
		"caller scalar":        {"schema_version: 2\nconnections:\n  a:\n    callers:\n      agent: allow\n", "the word deny"},
		"caller kind":          {"schema_version: 2\nconnections:\n  a:\n    callers:\n      root: deny\n", "not a caller kind"},
		"bad tier":             {"schema_version: 2\nconnections:\n  a:\n    callers:\n      agent: {tiers: [D9]}\n", "schema"},
		"D6 for an agent":      {"schema_version: 2\nconnections:\n  a:\n    callers:\n      agent: {tiers: [D6]}\n", "D6"},
		"command unknown conn": {"schema_version: 2\nconnections: {a: {}}\ncommands:\n  - {match: [/usr/bin/x], connections: [b]}\n", `connection "b"`},
		"command no conns":     {"schema_version: 2\nconnections: {a: {}}\ncommands:\n  - {match: [/usr/bin/x]}\n", "names no connections"},
		"relative command":     {"schema_version: 2\nconnections: {a: {}}\ncommands:\n  - {match: [x], connections: [a]}\n", "absolute path"},
		"bad host":             {"schema_version: 2\nconnections: {a: {hosts: ['*']}}\n", "hosts"},
	} {
		_, err := ParseYAML([]byte(tc.doc))
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), tc.why, name)
	}
}

func TestParseYAMLDocumentsSurviveARoundTrip(t *testing.T) {
	docs, err := ParseYAML([]byte(yamlPolicyFile))
	require.NoError(t, err)
	for name, d := range docs {
		b, err := Marshal(d)
		require.NoError(t, err)
		again, err := Parse(b)
		require.NoError(t, err, name)
		assert.Equal(t, d, again, name)
	}
}

func TestDescribeShowsTiersApprovalAndHostBounds(t *testing.T) {
	docs, err := ParseYAML([]byte(yamlPolicyFile))
	require.NoError(t, err)
	line := Describe(docs["stripe-test"])
	assert.Contains(t, line, "agent=allow[")
	assert.Contains(t, line, "tiers=D2,D3")
	assert.Contains(t, line, "approval=auto")
	assert.Contains(t, line, "hosts=api.stripe.com:443,files.stripe.com:443")
	bounded := docs["stripe-test"].WithHost(HostBounds{Source: "codex", EgressRestricted: true})
	assert.Contains(t, Describe(bounded), "host=codex")
	assert.True(t, strings.Contains(strings.Join(Diff(map[string]Document{"stripe-test": docs["stripe-test"]}, map[string]Document{"stripe-test": bounded}), "\n"), "host=codex"),
		"importing host bounds shows in the diff a human approves")
}
