package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/explain"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/policy"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/testutil"
)

func withCustomBinding(t *testing.T, known map[string]registry.CustomBinding) {
	t.Helper()
	prev := customBinding
	customBinding = func(_ context.Context, name string) (registry.Binding, error) {
		b, ok := known[name]
		if !ok {
			return registry.Binding{}, errors.New("not found")
		}
		return b.Binding(name), nil
	}
	t.Cleanup(func() { customBinding = prev })
}

func billingBinding() registry.CustomBinding {
	h := []string{"api.billing.example:443"}
	return registry.CustomBinding{
		Hosts: h,
		Slots: []registry.Slot{{Field: "token", In: registry.SlotHeader, Name: "Authorization", Scheme: "Bearer", Hosts: h}},
		Shape: registry.PlaceholderShape{MinLength: 32},
		Env:   map[string]string{"token": "BILLING_API_KEY"},
	}
}

func TestResolveConnectionReadsHostsAndSlotsFromBindings(t *testing.T) {
	withCustomBinding(t, map[string]registry.CustomBinding{"billing-internal": billingBinding()})
	ctx := context.Background()
	require.NoError(t, registry.InitFromConfig(ctx, llmcontext.DefaultLookup))

	tmpl := resolveConnection(ctx, "stripe")
	require.True(t, tmpl.Known)
	require.NotNil(t, tmpl.Binding)
	assert.Equal(t, explain.BindingTemplate, tmpl.Binding.Source)
	assert.Equal(t, tmpl.Binding.Hosts, tmpl.Hosts, "hosts come from the binding, not the allowed-hosts table")
	assert.NotEmpty(t, tmpl.Binding.Slots)

	custom := resolveConnection(ctx, "billing-internal")
	require.True(t, custom.Known)
	assert.Equal(t, explain.BindingCustom, custom.Binding.Source)
	assert.Equal(t, []string{"api.billing.example:443"}, custom.Hosts)
	assert.Equal(t, explain.SlotInfo{Field: "token", In: "header", Name: "Authorization", Hosts: []string{"api.billing.example:443"}}, custom.Binding.Slots[0])

	assert.False(t, resolveConnection(ctx, "nope-nothing").Known, "a name with no template or binding is unknown")
	assert.False(t, resolveConnection(ctx, "Not A Name").Known, "an invalid custom name never reaches the store")
}

func TestExplainRunReportsACustomConnectionAndAMissingBinding(t *testing.T) {
	testutil.ClearLLMSessionEnv(t)
	withCustomBinding(t, map[string]registry.CustomBinding{"billing-internal": billingBinding()})
	path := filepath.Join(t.TempDir(), "policy.json")
	require.NoError(t, policy.Save(path, policy.Policy{SchemaVersion: 1, Mode: policy.ModeEnforcing, DefaultDeny: false}))
	t.Setenv("KEYLATCH_POLICY_PATH", path)

	run := func(connection string) explain.Report {
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&bytes.Buffer{})
		root.SetArgs([]string{"explain", "--json", "run", "--actor", "human-shell", connection, "--", "node", "sync.js"})
		require.NoError(t, root.Execute())
		var rep explain.Report
		require.NoError(t, json.Unmarshal(out.Bytes(), &rep))
		return rep
	}

	rep := run("billing-internal")
	require.NotNil(t, rep.Binding)
	assert.Equal(t, explain.BindingCustom, rep.Binding.Source)
	assert.Equal(t, []string{"api.billing.example:443"}, rep.Hosts)

	// A provider whose template declares no bindings cannot be served at D3.
	require.NoError(t, registry.InitFromConfig(context.Background(), llmcontext.DefaultLookup))
	unbound := ""
	for _, tmpl := range registry.List() {
		if _, ok := tmpl.Binding(); !ok && len(tmpl.RuntimeSupport.Supported) > 0 {
			unbound = tmpl.Provider
			break
		}
	}
	require.NotEmpty(t, unbound, "the catalog has a provider without bindings")
	rep = run(unbound)
	assert.Nil(t, rep.Binding)
	var d3 explain.Rejected
	for _, r := range rep.Rejected {
		if r.Tier == "D3" {
			d3 = r
		}
	}
	assert.Equal(t, "no_binding", d3.Code)
	assert.Contains(t, d3.Fix, "keylatch connect "+unbound+" --provider custom --host")
}

func TestWriteRunTextShowsTheBindingAndTheFix(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, writeRunText(&out, explain.Report{
		Decision: "deny", ChildLocation: "none", Containment: explain.Containment{Verdict: "not_applicable"},
		Binding:  &explain.BindingInfo{Source: "custom", Slots: []explain.SlotInfo{{Field: "token"}}},
		Rejected: []explain.Rejected{{Tier: "D3", TierName: "placeholder_substitution", Why: "no_binding: x", Code: "no_binding", Fix: "keylatch connect x --provider custom"}},
	}))
	assert.Contains(t, out.String(), "binding:      custom, 1 slot(s)")
	assert.Contains(t, out.String(), "fix: keylatch connect x --provider custom")
}
