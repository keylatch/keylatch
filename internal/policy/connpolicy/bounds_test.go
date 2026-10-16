package connpolicy

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/registry"
)

var (
	hostUniverse = []string{
		"api.a.com", "b.a.com", "*.a.com", "*.b.a.com", "c.d.com", "*.d.com", "x.org:8443", "api.a.com:8443", "*.a.com:8443", "z.example.net",
	}
	// probes are literal destinations used to compare what two lists allow.
	probes = []string{
		"api.a.com", "b.a.com", "z.a.com", "q.b.a.com", "a.com", "c.d.com", "e.d.com", "d.com", "x.org", "api.a.com:8443", "z.a.com:8443",
		"x.org:8443", "z.example.net", "y.example.net", "deep.q.b.a.com",
	}
	pathUniverse = []string{
		"/work", "/work/project", "/work/project/sub", "/tmp", "/etc", "/home/u/.ssh", "~/.cache", "~/.cache/build", "~/.ssh",
		"${project}", "${project}/sub", "${toolchain_caches}", "${keylatch_state}",
	}
)

func pick(r *rand.Rand, universe []string) []string {
	var out []string
	for _, u := range universe {
		if r.IntN(3) == 0 {
			out = append(out, u)
		}
	}
	return out
}

func allows(list []string, probe string) bool {
	return slices.ContainsFunc(list, func(p string) bool { return registry.MatchAuthority(p, normalizeAuthority(probe)) })
}

func TestIntersectHostsIsExactlyWhatBothListsAllow(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for range 2000 {
		a, b := pick(r, hostUniverse), pick(r, hostUniverse)
		got := IntersectHosts(a, b)
		for _, p := range probes {
			assert.Equal(t, allows(a, p) && allows(b, p), allows(got, p), "probe %s\n a=%v\n b=%v\n got=%v", p, a, b, got)
		}
		assert.ElementsMatch(t, got, IntersectHosts(b, a), "intersection is commutative")
		assert.ElementsMatch(t, IntersectHosts(a, a), dedupe(a), "intersecting a list with itself keeps it")
		assert.Empty(t, IntersectHosts(a, nil), "an empty list allows nothing")
	}
}

func dedupe(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

func TestIntersectPathsIsExactlyWhatBothListsAllow(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	probe := append(slices.Clone(pathUniverse), "/work/project/sub/deeper", "/tmp/x", "/elsewhere", "${project}/sub/deeper", "~/.cache/build/obj")
	for range 2000 {
		a, b := pick(r, pathUniverse), pick(r, pathUniverse)
		got := IntersectPaths(a, b)
		for _, p := range probe {
			assert.Equal(t, WithinAny(p, a) && WithinAny(p, b), WithinAny(p, got), "probe %s\n a=%v\n b=%v\n got=%v", p, a, b, got)
		}
		assert.Equal(t, got, IntersectPaths(b, a))
		assert.Empty(t, IntersectPaths(a, nil))
		u := UnionPaths(a, b)
		for _, p := range probe {
			assert.Equal(t, WithinAny(p, a) || WithinAny(p, b), WithinAny(p, u))
		}
	}
}

func TestPathWithin(t *testing.T) {
	for _, tc := range []struct {
		child, parent string
		want          bool
	}{
		{"/a/b", "/a", true}, {"/a", "/a", true}, {"/ab", "/a", false}, {"/a", "/a/b", false}, {"/a/b/", "/a", true},
		{"~/x", "~", true}, {"~/x/y", "~/x", true}, {"~/x", "/home/u/x", false},
		{"${project}/s", "${project}", true}, {"${project}", "${project}/s", false}, {"${project}", "${keylatch_state}", false},
		{"/", "/", true}, {"/a", "/", true}, {"relative", "/", false}, {"/a", "relative", false},
	} {
		assert.Equal(t, tc.want, PathWithin(tc.child, tc.parent), "%s within %s", tc.child, tc.parent)
	}
}

func randomDocument(r *rand.Rand) Document {
	d := Document{SchemaVersion: SchemaVersion, Connection: "c", Callers: map[callerkind.Kind]CallerRule{}}
	d.Hosts = pick(r, hostUniverse)
	d.Egress = &Egress{Allow: pick(r, hostUniverse)}
	d.FS = &FS{Read: pick(r, pathUniverse), Write: pick(r, pathUniverse), Deny: pick(r, pathUniverse)}
	for _, k := range Kinds {
		if r.IntN(4) == 0 {
			continue
		}
		rule := CallerRule{Allow: r.IntN(5) != 0}
		if rule.Allow && r.IntN(2) == 0 {
			rule.Tiers = nil
			for _, tier := range AllTiers[:5] {
				if r.IntN(2) == 0 {
					rule.Tiers = append(rule.Tiers, tier)
				}
			}
			if len(rule.Tiers) == 0 {
				rule.Tiers = []string{D2}
			}
		}
		d.Callers[k] = rule
	}
	return d
}

func randomHost(r *rand.Rand) HostBounds {
	b := HostBounds{Source: "claude-code", FSDeny: pick(r, pathUniverse)}
	if r.IntN(2) == 0 {
		b.EgressRestricted, b.EgressAllow = true, pick(r, hostUniverse)
	}
	if r.IntN(2) == 0 {
		b.WriteRestricted, b.FSWrite = true, pick(r, pathUniverse)
	}
	return b
}

// An import records limits and nothing else: whatever a document denies stays
// denied, and everything it still allows is allowed by the original too.
func TestImportNeverWidensWhatADocumentAllows(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	for range 3000 {
		doc := randomDocument(r)
		bounded := doc.WithHost(randomHost(r))
		for _, kind := range Kinds {
			for _, tier := range append([]string{""}, AllTiers...) {
				req := Request{Caller: kind, Tier: tier}
				before, after := doc.Decide(req), bounded.Decide(req)
				if after.Allow {
					require.True(t, before.Allow, "the import allowed %s at %s: %+v", kind, tier, bounded)
				}
				if !after.Allow {
					continue
				}
				for _, h := range probes {
					if allows(after.Egress, h) {
						require.True(t, allows(before.Egress, h), "egress to %s widened", h)
					}
				}
				for _, p := range pathUniverse {
					if WithinAny(p, before.FSDeny) {
						require.True(t, WithinAny(p, after.FSDeny), "a deny on %s was lost", p)
					}
				}
				require.Equal(t, before.Tiers, after.Tiers)
				require.Equal(t, before.Approval, after.Approval)
				require.Equal(t, before.MaxTTL, after.MaxTTL)
			}
		}
		// Writes: what the bounded document allows, the original allows.
		for _, p := range pathUniverse {
			if bounded.WriteAllowed(p, doc.FS.Write) {
				assert.True(t, doc.WriteAllowed(p, doc.FS.Write), "writes under %s widened", p)
			}
		}
	}
}

func TestEffectiveEgressIsTheIntersectionWithTheHost(t *testing.T) {
	d := Document{Egress: &Egress{Allow: []string{"registry.npmjs.org", "*.pnpm.io", "evil.example"}}}
	assert.Equal(t, []string{"registry.npmjs.org", "*.pnpm.io", "evil.example"}, d.EffectiveEgress())

	bounded := d.WithHost(HostBounds{Source: "claude-code", EgressRestricted: true, EgressAllow: []string{"registry.npmjs.org", "cdn.pnpm.io", "other.example"}})
	assert.ElementsMatch(t, []string{"registry.npmjs.org", "cdn.pnpm.io"}, bounded.EffectiveEgress())

	none := d.WithHost(HostBounds{Source: "codex", EgressRestricted: true})
	assert.Empty(t, none.EffectiveEgress(), "a host that allows no domain leaves no destination")

	empty := Document{}.WithHost(HostBounds{Source: "claude-code", EgressRestricted: true, EgressAllow: []string{"a.com"}})
	assert.Empty(t, empty.EffectiveEgress(), "a host list never adds a destination the document lacks")
}

func TestEffectiveHostsNarrowTheTemplate(t *testing.T) {
	template := []string{"api.stripe.com", "files.stripe.com", "*.edge.stripe.com"}
	assert.Equal(t, template, Document{}.EffectiveHosts(template))
	d := Document{Hosts: []string{"api.stripe.com", "x.edge.stripe.com"}}
	assert.ElementsMatch(t, []string{"api.stripe.com", "x.edge.stripe.com"}, d.EffectiveHosts(template))
	assert.Empty(t, Document{Hosts: []string{"other.example"}}.EffectiveHosts(template), "a host the template does not name is never added")
	assert.Equal(t, template, IntersectHostsIfAny(template, nil))
}

func TestWriteAllowedHonoursBothLimits(t *testing.T) {
	d := Document{}.WithHost(HostBounds{Source: "claude-code", WriteRestricted: true, FSWrite: []string{"/work"}})
	assert.True(t, d.WriteAllowed("/work/p", []string{"/work/p"}))
	assert.False(t, d.WriteAllowed("/other", []string{"/other"}), "the host sandbox does not allow it")
	assert.False(t, d.WriteAllowed("/work/p", []string{"/work/q"}), "the document does not allow it")
	assert.True(t, Document{}.WriteAllowed("/anywhere", nil), "with no limit anything the caller expands is allowed")
}

func TestNarrowerPicksTheCoveredPattern(t *testing.T) {
	for _, tc := range []struct {
		a, b, want string
		ok         bool
	}{
		{"api.a.com", "api.a.com", "api.a.com", true},
		{"*.a.com", "api.a.com", "api.a.com", true},
		{"api.a.com", "*.a.com", "api.a.com", true},
		{"*.a.com", "*.b.a.com", "*.b.a.com", true},
		{"*.b.a.com", "*.a.com", "*.b.a.com", true},
		{"*.a.com", "*.d.com", "", false},
		{"api.a.com", "api.a.com:8443", "", false},
		{"a.com", "*.a.com", "", false},
	} {
		got, ok := narrower(tc.a, tc.b)
		assert.Equal(t, tc.ok, ok, "%s %s", tc.a, tc.b)
		assert.Equal(t, tc.want, got, "%s %s", tc.a, tc.b)
	}
	assert.Equal(t, "x.org:443", normalizeAuthority(" X.org "))
}

func TestValidatePathVariants(t *testing.T) {
	for _, ok := range []string{"/", "/etc", "~", "~/x", "${project}", "${project}/sub", "${toolchain_caches}"} {
		assert.NoError(t, validatePath(ok), ok)
	}
	for _, bad := range []string{"", "rel", "${nope}", "${project", "/a/../b", "~/../x", "${project}/../x", "a\x00b"} {
		assert.Error(t, validatePath(bad), strings.ReplaceAll(bad, "\x00", "NUL"))
	}
}
