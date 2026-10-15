package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/examples"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/policy/connpolicy"
	"github.com/keylatch/keylatch/internal/policy/enforce"
	"github.com/keylatch/keylatch/internal/presence/presencetest"
)

// policyTestDir points the policy locations at a fresh directory and makes
// the process use the real enforcer, which the package default replaces with
// allow-all for tests that are not about policy.
func policyTestDir(t *testing.T) string {
	t.Helper()
	dir := presenceTestEnv(t)
	t.Setenv("KEYLATCH_POLICY_PATH", "")
	t.Cleanup(enforce.SetDefault(nil))
	return dir
}

func writeExampleDir(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	entries, err := examples.PolicyD.ReadDir("policy.d")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if len(names) > 0 && !contains(names, e.Name()) {
			continue
		}
		data, _ := examples.PolicyD.ReadFile("policy.d/" + e.Name())
		if err := os.WriteFile(filepath.Join(dir, e.Name()), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func storeDocs(t *testing.T) map[string]connpolicy.Document {
	t.Helper()
	docs, err := (connpolicy.Store{Dir: paths.PolicyDir(llmcontext.DefaultLookup)}).LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	return docs
}

func TestExamplesValidate(t *testing.T) {
	docs, err := exampleDocuments()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"*", "openrouter", "vercel", "stripe"} {
		if _, ok := docs[name]; !ok {
			t.Errorf("no example for connection %q", name)
		}
	}
	entries, _ := examples.PolicyD.ReadDir("policy.d")
	if len(entries) != 4 || len(docs) != 4 {
		t.Errorf("examples: %d files, %d connections; want 4 and 4", len(entries), len(docs))
	}
}

func TestPolicyInitWritesDefaultDeny(t *testing.T) {
	dir := policyTestDir(t)

	if _, err := runCLI(t, "policy", "init"); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"policy.json", "policy.d/_default.json", "policy.examples/agent-gateway-only.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	if _, err := runCLI(t, "policy", "init"); err == nil {
		t.Fatal("init replaced an existing policy without --force")
	}

	for kind, want := range map[string]bool{"human": true, "agent": false, "host": false, "service": false} {
		out, err := runCLI(t, "policy", "check", "anything", "--as", kind, "--json")
		if (err == nil) != want {
			t.Errorf("check as %s: err=%v, want allow=%v (%s)", kind, err, want, out)
		}
	}
}

func TestPolicyInitForceNeedsPresence(t *testing.T) {
	policyTestDir(t)
	if _, err := runCLI(t, "policy", "init"); err != nil {
		t.Fatal(err)
	}
	presencetest.NoTerminal(t)
	_, err := runCLI(t, "policy", "init", "--force")
	requireExitCode(t, err, exitcode.SecurityBlock)
}

func TestPolicyMutationNeedsPresence(t *testing.T) {
	dir := policyTestDir(t)
	presencetest.NoTerminal(t)

	for _, args := range [][]string{
		{"policy", "allow", "*", "*"},
		{"policy", "allow", "claude-code", "stripe", "--capability", "*"},
		{"policy", "deny", "stripe", "--as", "agent"},
		{"policy", "remove", "some-rule"},
		{"policy", "import", writeExampleDir(t)},
		{"grant", "create", "stripe", "--actor", "claude-code"},
	} {
		_, err := runCLI(t, args...)
		requireExitCode(t, err, exitcode.SecurityBlock)
	}
	for _, f := range []string{"policy.json", "policy.d", "grants.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			t.Errorf("%s was written without presence", f)
		}
	}
}

func TestPolicyAllowSummaryNamesTheRule(t *testing.T) {
	policyTestDir(t)
	seen := presencetest.Record(t)
	if _, err := runCLI(t, "policy", "allow", "dev", "stripe", "--capability", "inject", "--runtime", "gateway_typed"); err != nil {
		t.Fatal(err)
	}
	if len(*seen) != 1 || !strings.Contains((*seen)[0], `"dev"`) || !strings.Contains((*seen)[0], `"stripe"`) || !strings.Contains((*seen)[0], "gateway_typed") {
		t.Fatalf("summaries = %q", *seen)
	}
}

func TestPolicyImportNeedsPresence(t *testing.T) {
	policyTestDir(t)
	presencetest.NoTerminal(t)
	_, err := runCLI(t, "policy", "import", writeExampleDir(t))
	requireExitCode(t, err, exitcode.SecurityBlock)
	if len(storeDocs(t)) != 0 {
		t.Fatal("documents were imported without presence")
	}
}

func TestPolicyImportAtomic(t *testing.T) {
	policyTestDir(t)
	presencetest.Approve(t)

	// A valid set is in place.
	if _, err := runCLI(t, "policy", "import", writeExampleDir(t, "human-only.json")); err != nil {
		t.Fatal(err)
	}
	before := storeDocs(t)
	if len(before) != 1 {
		t.Fatalf("setup: %v", before)
	}

	// One valid and one invalid file: nothing changes.
	dir := writeExampleDir(t, "agent-gateway-only.json", "service-only.json")
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte(`{"schema_version": 2, "connection": "x", "callers": {"agent": {"allow": true, "tiers": ["D1"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runCLI(t, "policy", "import", dir)
	requireExitCode(t, err, exitcode.UserError)
	if !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("err = %v", err)
	}
	after := storeDocs(t)
	if len(after) != 1 || connpolicy.Describe(after["stripe"]) != connpolicy.Describe(before["stripe"]) {
		t.Fatalf("a rejected import changed the policy: %v", after)
	}
}

func TestPolicyImportShowsTheDiffAndReplaces(t *testing.T) {
	policyTestDir(t)
	seen := presencetest.Record(t)

	out, err := runCLI(t, "policy", "import", writeExampleDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(storeDocs(t)) != 4 {
		t.Fatalf("imported %d documents, want 4", len(storeDocs(t)))
	}
	for _, want := range []string{"+ openrouter:", "+ stripe:", "+ vercel:", "+ *:"} {
		if !strings.Contains(out, want) {
			t.Errorf("diff output lacks %q:\n%s", want, out)
		}
		if len(*seen) != 1 || !strings.Contains((*seen)[0], want) {
			t.Errorf("the approved summary lacks %q: %q", want, *seen)
		}
	}

	// Importing the same set again is a no-op and asks nobody.
	*seen = nil
	if out, err := runCLI(t, "policy", "import", writeExampleDir(t)); err != nil || !strings.Contains(out, "no changes") || len(*seen) != 0 {
		t.Fatalf("second import: %q, %v, asked %q", out, err, *seen)
	}
}

func TestPolicyExportRoundTrip(t *testing.T) {
	policyTestDir(t)
	presencetest.Approve(t)
	if _, err := runCLI(t, "policy", "import", writeExampleDir(t)); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "exported")
	if _, err := runCLI(t, "policy", "export", out); err != nil {
		t.Fatal(err)
	}
	if _, err := runCLI(t, "policy", "export", out); err == nil {
		t.Fatal("export overwrote existing files without --force")
	}
	if text, err := runCLI(t, "policy", "import", out); err != nil || !strings.Contains(text, "no changes") {
		t.Fatalf("re-import of an export: %q, %v", text, err)
	}
}

func TestPolicyDenyNarrowsADocument(t *testing.T) {
	policyTestDir(t)
	presencetest.Approve(t)
	if _, err := runCLI(t, "policy", "import", writeExampleDir(t, "agent-gateway-only.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := runCLI(t, "policy", "check", "openrouter", "--as", "agent", "--runtime", "gateway_typed"); err != nil {
		t.Fatalf("agent should be allowed first: %v", err)
	}
	if _, err := runCLI(t, "policy", "deny", "openrouter", "--as", "agent"); err != nil {
		t.Fatal(err)
	}
	_, err := runCLI(t, "policy", "check", "openrouter", "--as", "agent", "--runtime", "gateway_typed")
	requireExitCode(t, err, exitcode.PolicyDeny)
}

// policy check is read-only and agrees with enforce.Decide for every example
// document, caller kind and runtime.
func TestPolicyCheckMatchesEnforce(t *testing.T) {
	policyTestDir(t)
	presencetest.Approve(t)
	if _, err := runCLI(t, "policy", "import", writeExampleDir(t)); err != nil {
		t.Fatal(err)
	}
	presencetest.NoTerminal(t) // check must not need presence

	var checked int
	for conn := range storeDocs(t) {
		target := conn
		if target == "*" {
			target = "some-other-connection"
		}
		for _, kind := range connpolicy.Kinds {
			for _, rt := range []string{"", "gateway_typed", "gateway_sdk", "direct_brokered"} {
				args := []string{"policy", "check", target, "--as", string(kind), "--json"}
				if rt != "" {
					args = append(args, "--runtime", rt)
				}
				out, _ := runCLI(t, args...)
				var got policyCheckResult
				if err := json.Unmarshal([]byte(out), &got); err != nil {
					t.Fatalf("%v: output %q: %v", args, out, err)
				}
				want := enforce.Decide(context.Background(), enforce.Request{
					Connection: target, Action: enforce.DefaultAction, Runtime: rt, Caller: kind,
				})
				if got.Allow != want.Allow || got.Reason != want.Reason || got.Source != want.Source || got.MaxTTLSeconds != int(want.MaxTTL.Seconds()) {
					t.Errorf("%v: check = %+v, Decide = %+v", args, got, want)
				}
				checked++
			}
		}
	}
	if checked != 4*4*4 {
		t.Fatalf("checked %d combinations", checked)
	}
}

func TestPolicyCheckRejectsBadInput(t *testing.T) {
	policyTestDir(t)
	for _, args := range [][]string{
		{"policy", "check", "x", "--as", "root"},
		{"policy", "check", "x", "--as", "agent", "--runtime", "warp_drive"},
		{"policy", "check", "--as", "agent"},
		{"policy", "check", "a", "b", "--as", "agent"},
	} {
		_, err := runCLI(t, args...)
		if err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

func TestAgentRunPolicyKinds(t *testing.T) {
	policyTestDir(t)
	presencetest.Approve(t)
	if _, err := runCLI(t, "policy", "import", writeExampleDir(t, "agent-gateway-only.json")); err != nil {
		t.Fatal(err)
	}
	d := enforce.Decide(context.Background(), enforce.Request{Connection: "openrouter", Runtime: "gateway_typed", Caller: callerkind.Agent})
	if !d.Allow {
		t.Fatalf("agent under gateway_typed denied: %s", d.Reason)
	}
	if d := enforce.Decide(context.Background(), enforce.Request{Connection: "stripe", Runtime: "gateway_typed", Caller: callerkind.Agent}); d.Allow {
		t.Fatal("agent allowed on a connection with no policy")
	}
}
