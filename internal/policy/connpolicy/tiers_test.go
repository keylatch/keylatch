package connpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/callerkind"
)

func TestDefaultsFollowTheCallerKind(t *testing.T) {
	assert.Equal(t, []string{D1, D2, D3, D4}, DefaultTiers(callerkind.Agent))
	assert.Equal(t, []string{D1, D2, D3, D4}, DefaultTiers(callerkind.Host))
	assert.Equal(t, []string{D1, D2, D3, D4, D5}, DefaultTiers(callerkind.Service))
	assert.Equal(t, AllTiers, DefaultTiers(callerkind.Human))
	assert.Equal(t, ApprovalAutoIfContained, DefaultApproval(callerkind.Agent))
	assert.Equal(t, ApprovalPresenceForD6, DefaultApproval(callerkind.Human))
	assert.Equal(t, ApprovalAuto, DefaultApproval(callerkind.Service))
}

func TestResolveApproval(t *testing.T) {
	for _, tc := range []struct {
		mode, tier string
		pinned     bool
		want       string
	}{
		{ApprovalAutoIfContained, D1, false, "auto"},
		{ApprovalAutoIfContained, D3, false, "auto"},
		{ApprovalAutoIfContained, D4, false, "auto"},
		{ApprovalAutoIfContained, D5, false, "ask"},
		{ApprovalAutoIfContained, D5, true, "auto"},
		{ApprovalAutoIfContained, D6, true, "presence"},
		{ApprovalPresenceForD6, D5, false, "auto"},
		{ApprovalPresenceForD6, D6, false, "presence"},
		{ApprovalAuto, D5, false, "auto"},
		{ApprovalAuto, D6, false, "presence"},
		{ApprovalAsk, D2, false, "ask"},
		{ApprovalPresence, D3, false, "presence"},
	} {
		assert.Equal(t, tc.want, ResolveApproval(tc.mode, tc.tier, tc.pinned), "%s at %s pinned=%v", tc.mode, tc.tier, tc.pinned)
	}
}

func TestMatchArgv(t *testing.T) {
	for name, tc := range map[string]struct {
		pattern, argv []string
		exe           string
		want          bool
	}{
		"exact":                 {[]string{"/usr/bin/pnpm", "test"}, []string{"pnpm", "test"}, "/usr/bin/pnpm", true},
		"extra argument":        {[]string{"/usr/bin/pnpm", "test"}, []string{"pnpm", "test", "--watch"}, "/usr/bin/pnpm", false},
		"missing argument":      {[]string{"/usr/bin/pnpm", "test"}, []string{"pnpm"}, "/usr/bin/pnpm", false},
		"one wildcard":          {[]string{"/usr/bin/pnpm", "run", "*"}, []string{"pnpm", "run", "build"}, "/usr/bin/pnpm", true},
		"wildcard needs an arg": {[]string{"/usr/bin/pnpm", "run", "*"}, []string{"pnpm", "run"}, "/usr/bin/pnpm", false},
		"rest":                  {[]string{"/usr/bin/pnpm", "test", "**"}, []string{"pnpm", "test", "a", "b", "c"}, "/usr/bin/pnpm", true},
		"rest matches nothing":  {[]string{"/usr/bin/pnpm", "test", "**"}, []string{"pnpm", "test"}, "/usr/bin/pnpm", true},
		"rest not last":         {[]string{"/usr/bin/pnpm", "**", "test"}, []string{"pnpm", "x", "test"}, "/usr/bin/pnpm", false},
		"partial glob":          {[]string{"/usr/bin/go", "test", "./pkg/*"}, []string{"go", "test", "./pkg/a"}, "/usr/bin/go", true},
		"question mark":         {[]string{"/usr/bin/go", "-v?"}, []string{"go", "-v1"}, "/usr/bin/go", true},
		"other executable":      {[]string{"/usr/bin/pnpm", "test"}, []string{"pnpm", "test"}, "/tmp/pnpm", false},
		"exe glob":              {[]string{"/usr/bin/*", "test"}, []string{"x", "test"}, "/usr/bin/anything", true},
		"exe glob stays in dir": {[]string{"/usr/bin/*", "test"}, []string{"x", "test"}, "/usr/bin/sub/anything", false},
		"exe double star":       {[]string{"/opt/**/bin/tool"}, []string{"tool"}, "/opt/a/b/bin/tool", true},
		"exe double star none":  {[]string{"/opt/**/bin/tool"}, []string{"tool"}, "/opt/bin/tool", true},
		"relative pattern":      {[]string{"pnpm", "test"}, []string{"pnpm", "test"}, "/usr/bin/pnpm", false},
		"empty pattern":         {nil, []string{"pnpm"}, "/usr/bin/pnpm", false},
		"empty argv":            {[]string{"/usr/bin/pnpm"}, nil, "/usr/bin/pnpm", false},
		"no resolved exe":       {[]string{"/usr/bin/pnpm"}, []string{"pnpm"}, "", false},
		"empty literal":         {[]string{"/usr/bin/x", ""}, []string{"x", ""}, "/usr/bin/x", true},
		"empty literal vs arg":  {[]string{"/usr/bin/x", ""}, []string{"x", "a"}, "/usr/bin/x", false},
	} {
		assert.Equal(t, tc.want, MatchArgv(tc.pattern, tc.argv, tc.exe), name)
	}
}

func FuzzPolicyArgvMatch(f *testing.F) {
	f.Add("/usr/bin/pnpm\ntest\n**", "pnpm\ntest\nx", "/usr/bin/pnpm")
	f.Add("/usr/bin/*\n*", "a\nb", "/usr/bin/a")
	f.Add("/opt/**/tool\n?x", "t\nax", "/opt/a/b/tool")
	f.Add("\n", "\n", "")
	f.Add("/a\n**\nb", "a\nx\nb", "/a")
	f.Fuzz(func(t *testing.T, pattern, argv, exe string) {
		p, a := strings.Split(pattern, "\n"), strings.Split(argv, "\n")
		if !MatchArgv(p, a, exe) {
			return
		}
		// A match implies the pattern's first word is an absolute path pattern,
		// every argument before a rest wildcard fits its pattern, and a pattern
		// without wildcards matches only itself.
		if !filepath.IsAbs(p[0]) {
			t.Fatalf("a relative executable pattern %q matched", p[0])
		}
		if !pathGlob(p[0], exe) {
			t.Fatalf("the executable %q does not fit %q", exe, p[0])
		}
		plain := true
		for _, w := range p {
			plain = plain && !strings.ContainsAny(w, "*?")
		}
		if plain && !equalFrom(p, a) {
			t.Fatalf("a wildcard-free pattern %q matched %q", p, a)
		}
	})
}

func equalFrom(p, a []string) bool {
	if len(p) != len(a) {
		return false
	}
	for i := 1; i < len(p); i++ {
		if p[i] != a[i] {
			return false
		}
	}
	return true
}

func TestResolveExecutable(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	require.NoError(t, os.Mkdir(bin, 0o755))
	tool := filepath.Join(bin, "tool-real")
	require.NoError(t, os.WriteFile(tool, []byte("#!/bin/sh\n"), 0o755))
	require.NoError(t, os.Symlink("tool-real", filepath.Join(bin, "tool")))
	require.NoError(t, os.WriteFile(filepath.Join(bin, "data"), nil, 0o644))
	real, err := filepath.EvalSymlinks(tool)
	require.NoError(t, err)

	got, err := ResolveExecutable("tool", dir, bin+":/nonexistent")
	require.NoError(t, err)
	assert.Equal(t, real, got, "a symlink resolves to what would run")
	got, err = ResolveExecutable("./bin/tool", dir, "")
	require.NoError(t, err)
	assert.Equal(t, real, got)
	got, err = ResolveExecutable(tool, "", "")
	require.NoError(t, err)
	assert.Equal(t, real, got)

	for _, argv0 := range []string{"", "missing", "data", "./bin/missing", "bin"} {
		_, err = ResolveExecutable(argv0, dir, bin)
		assert.Error(t, err, argv0)
	}
	_, err = ResolveExecutable("tool", dir, "relative:"+"")
	assert.Error(t, err, "a relative PATH entry is not searched")
}

func TestVerifyPinnedRefusesWhatARootCannotVouchFor(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "tool")
	content := []byte("#!/bin/sh\necho hi\n")
	require.NoError(t, os.WriteFile(file, content, 0o755))
	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])

	assert.ErrorContains(t, VerifyPinned(file, "short"), "64 hex digits")
	assert.Error(t, VerifyPinned(filepath.Join(dir, "missing"), want))
	// A file the test user owns is not owned by root, however well it hashes.
	if os.Getuid() != 0 {
		assert.ErrorContains(t, VerifyPinned(file, want), "not owned by root")
	}
}

func TestVerifyPinnedAcceptsARootOwnedClosedExecutable(t *testing.T) {
	const candidate = "/bin/sh"
	real, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		t.Skip("no /bin/sh")
	}
	b, err := os.ReadFile(real)
	require.NoError(t, err)
	sum := sha256.Sum256(b)
	want := hex.EncodeToString(sum[:])
	if err := VerifyPinned(real, want); err != nil {
		t.Skipf("the system shell is not in a root-only location on this host: %v", err)
	}
	assert.ErrorContains(t, VerifyPinned(real, strings.Repeat("0", 64)), "pinned hash")
}

func TestTTLField(t *testing.T) {
	d, err := ttl("")
	assert.NoError(t, err)
	assert.Zero(t, d)
	d, err = ttl("90s")
	assert.NoError(t, err)
	assert.Equal(t, 90*time.Second, d)
	for _, bad := range []string{"soon", "-5m", "0s"} {
		_, err = ttl(bad)
		assert.Error(t, err, bad)
	}
}

func tierDoc(t *testing.T, callers string, extra string) Document {
	t.Helper()
	d, err := Parse([]byte(`{"schema_version": 2, "connection": "stripe",` + extra + ` "callers": {` + callers + `}}`))
	require.NoError(t, err)
	return d
}

func TestDecideTiers(t *testing.T) {
	d := tierDoc(t, `"agent": {"allow": true}, "human": {"allow": true}, "service": {"allow": true, "tiers": ["D2"]}, "host": {"allow": true, "tiers": ["D3", "D5"]}`, "")
	for name, tc := range map[string]struct {
		req      Request
		allow    bool
		approval string
	}{
		"agent D3 by default":      {Request{Caller: callerkind.Agent, Tier: D3}, true, "auto"},
		"agent D4 by default":      {Request{Caller: callerkind.Agent, Tier: D4}, true, "auto"},
		"agent D5 not by default":  {Request{Caller: callerkind.Agent, Tier: D5}, false, ""},
		"agent D6 never":           {Request{Caller: callerkind.Agent, Tier: D6}, false, ""},
		"human D5 automatic":       {Request{Caller: callerkind.Human, Tier: D5}, true, "auto"},
		"human D6 needs presence":  {Request{Caller: callerkind.Human, Tier: D6}, true, "presence"},
		"service limited to D2":    {Request{Caller: callerkind.Service, Tier: D3}, false, ""},
		"service D2":               {Request{Caller: callerkind.Service, Tier: D2}, true, "auto"},
		"host listed for D5 asks":  {Request{Caller: callerkind.Host, Tier: D5}, true, "ask"},
		"no tier asked":            {Request{Caller: callerkind.Agent}, true, ""},
		"unlisted tier for a host": {Request{Caller: callerkind.Host, Tier: D2}, false, ""},
	} {
		got := d.Decide(tc.req)
		assert.Equal(t, tc.allow, got.Allow, name+": "+got.Reason)
		assert.Equal(t, tc.approval, got.Approval, name)
	}
	denied := d.Decide(Request{Caller: callerkind.Agent, Tier: D5})
	assert.Contains(t, denied.Reason, "tier D5")
	assert.Contains(t, denied.Reason, "allowed: D1, D2, D3, D4")
}

func TestDecideApprovalAndLimitsFromTheCallerEntry(t *testing.T) {
	d := tierDoc(t, `"agent": {"allow": true, "tiers": ["D2", "D3", "D5"], "approval": "ask", "ttl": "5m", "max_requests": 40}`, `"max_ttl": "15m",`)
	got := d.Decide(Request{Caller: callerkind.Agent, Tier: D3})
	assert.Equal(t, "ask", got.Approval)
	assert.Equal(t, 5*time.Minute, got.MaxTTL, "the shorter of max_ttl and ttl")
	assert.Equal(t, 40, got.MaxRequests)

	d = tierDoc(t, `"agent": {"allow": true, "ttl": "30m"}`, `"max_ttl": "15m",`)
	assert.Equal(t, 15*time.Minute, d.Decide(Request{Caller: callerkind.Agent, Tier: D2}).MaxTTL)
}

func TestDecideCommandRules(t *testing.T) {
	pin := strings.Repeat("a", 64)
	d := tierDoc(t, `"agent": {"allow": true, "tiers": ["D2", "D3", "D5"]}`,
		`"commands": [
		   {"match": ["/usr/bin/pnpm", "test", "**"], "tiers": ["D3"]},
		   {"match": ["/usr/bin/make", "build"], "tiers": ["D5"], "exe_sha256": "`+pin+`"},
		   {"match": ["/usr/bin/curl", "**"], "approval": "ask"}
		 ],`)
	pins := func(err error) func(string, string) error {
		return func(path, sha string) error {
			assert.Equal(t, pin, sha)
			return err
		}
	}
	pnpm := Request{Caller: callerkind.Agent, Command: []string{"pnpm", "test", "--run"}, Exe: "/usr/bin/pnpm"}

	r := pnpm
	r.Tier = D3
	assert.True(t, d.Decide(r).Allow)
	r.Tier = D2
	got := d.Decide(r)
	assert.False(t, got.Allow, "a matched command is narrowed to its tiers")
	assert.Contains(t, got.Reason, "allowed: D3")

	other := Request{Caller: callerkind.Agent, Command: []string{"node", "x.js"}, Exe: "/usr/bin/node", Tier: D2}
	assert.True(t, d.Decide(other).Allow, "a command no rule matches is not narrowed")

	make := Request{Caller: callerkind.Agent, Command: []string{"make", "build"}, Exe: "/usr/bin/make", Tier: D5, Pins: pins(nil)}
	got = d.Decide(make)
	assert.True(t, got.Allow)
	assert.True(t, got.Pinned)
	assert.Equal(t, "auto", got.Approval, "a pinned command runs at D5 without an approval")

	make.Pins = pins(errors.New("sha mismatch"))
	got = d.Decide(make)
	assert.False(t, got.Allow, "a pin that no longer matches denies, never degrades to an unpinned run")
	assert.Contains(t, got.Reason, "sha mismatch")

	make.Command = []string{"make", "build", "extra"}
	make.Pins = pins(nil)
	got = d.Decide(make)
	assert.True(t, got.Allow)
	assert.False(t, got.Pinned)
	assert.Equal(t, "ask", got.Approval, "a different argv is not the pinned command")

	curl := Request{Caller: callerkind.Agent, Command: []string{"curl", "-s", "x"}, Exe: "/usr/bin/curl", Tier: D3}
	assert.Equal(t, "ask", d.Decide(curl).Approval, "a command rule can set the approval")
}

func TestHostsEgressAndFSComeBackWithTheDecision(t *testing.T) {
	d := tierDoc(t, `"agent": {"allow": true}`,
		`"hosts": ["api.stripe.com"],
		 "egress": {"allow": ["registry.npmjs.org", "*.pnpm.io"], "deny_private_ranges": true},
		 "fs": {"read": ["${project}", "${toolchain_caches}"], "write": ["${project}"], "deny": ["~/.ssh"]},`)
	got := d.Decide(Request{Caller: callerkind.Agent, Tier: D3})
	assert.Equal(t, []string{"api.stripe.com"}, got.Hosts)
	assert.Equal(t, []string{"registry.npmjs.org", "*.pnpm.io"}, got.Egress)
	assert.Equal(t, []string{"${project}", "${toolchain_caches}"}, got.FSRead)
	assert.Equal(t, []string{"${project}"}, got.FSWrite)
	assert.Equal(t, []string{"~/.ssh"}, got.FSDeny)
}

func TestValidateRejectsBadPolicyV2Fields(t *testing.T) {
	for name, doc := range map[string]string{
		"unknown tier":            `"callers": {"agent": {"allow": true, "tiers": ["D7"]}}`,
		"D6 for an agent":         `"callers": {"agent": {"allow": true, "tiers": ["D6"]}}`,
		"D6 for a host":           `"callers": {"host": {"allow": true, "tiers": ["D6"]}}`,
		"unknown approval":        `"callers": {"agent": {"allow": true, "approval": "maybe"}}`,
		"bad ttl":                 `"callers": {"agent": {"allow": true, "ttl": "soon"}}`,
		"negative max requests":   `"callers": {"agent": {"allow": true, "max_requests": -1}}`,
		"denied with a tier":      `"callers": {"agent": {"allow": false, "tiers": ["D2"]}}`,
		"bare wildcard host":      `"hosts": ["*"], "callers": {}`,
		"public suffix wildcard":  `"egress": {"allow": ["*.com"]}, "callers": {}`,
		"duplicate host":          `"hosts": ["a.example.com", "A.example.com"], "callers": {}`,
		"private ranges allowed":  `"egress": {"allow": [], "deny_private_ranges": false}, "callers": {}`,
		"relative fs path":        `"fs": {"write": ["relative/dir"]}, "callers": {}`,
		"unknown fs variable":     `"fs": {"write": ["${home}"]}, "callers": {}`,
		"dotdot in fs path":       `"fs": {"deny": ["/etc/../root"]}, "callers": {}`,
		"relative command":        `"commands": [{"match": ["pnpm", "test"]}], "callers": {}`,
		"rest not last":           `"commands": [{"match": ["/usr/bin/pnpm", "**", "x"]}], "callers": {}`,
		"bad pin":                 `"commands": [{"match": ["/usr/bin/pnpm"], "exe_sha256": "abc"}], "callers": {}`,
		"unknown command key":     `"commands": [{"match": ["/usr/bin/pnpm"], "bogus": 1}], "callers": {}`,
		"host bounds no source":   `"host": {"egress_restricted": true}, "callers": {}`,
		"host bounds bad egress":  `"host": {"source": "claude-code", "egress_allow": ["*"]}, "callers": {}`,
		"host bounds bad fs path": `"host": {"source": "claude-code", "fs_deny": ["nope"]}, "callers": {}`,
	} {
		_, err := Parse([]byte(`{"schema_version": 2, "connection": "stripe", ` + doc + `}`))
		assert.Error(t, err, name)
	}
}

func TestValidateAcceptsPolicyV2Fields(t *testing.T) {
	doc := `{"schema_version": 2, "connection": "stripe",
	  "hosts": ["api.stripe.com", "*.edge.stripe.com:443"],
	  "egress": {"allow": ["registry.npmjs.org"], "deny_private_ranges": true},
	  "fs": {"read": ["${project}", "/usr/share"], "write": ["${project}", "~/.cache/build"], "deny": ["${keylatch_state}", "~/.ssh", "${browser_profiles}", "${harness_config}"]},
	  "commands": [{"match": ["/usr/bin/pnpm", "test", "**"], "tiers": ["D3", "D4"], "approval": "auto", "exe_sha256": "` + strings.Repeat("0", 64) + `"}],
	  "host": {"source": "claude-code", "egress_restricted": true, "egress_allow": ["api.stripe.com"], "write_restricted": true, "fs_write": ["/work"], "fs_deny": ["~/.aws"]},
	  "callers": {"agent": {"allow": true, "tiers": ["D2", "D3", "D5"], "approval": "auto_if_contained", "ttl": "15m", "max_requests": 500}}}`
	d, err := Parse([]byte(doc))
	require.NoError(t, err)
	b, err := Marshal(d)
	require.NoError(t, err)
	again, err := Parse(b)
	require.NoError(t, err)
	assert.Equal(t, d, again, "a v2 document survives a round trip")
}
