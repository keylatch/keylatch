package path_test

import (
	"errors"
	"testing"

	vpath "github.com/keylatch/keylatch/internal/vault/path"
)

func TestCanonicalize_RejectsTraversalAndMalformedInput(t *testing.T) {
	cases := []string{
		"default/ai/openrouter/../../etc",
		"../default/ai/openrouter/api_key",
		"default/ai/openrouter/api_key/..",
		"openrouter...api_key",
		"/default/ai/openrouter/api_key",
		"default/ai/openrouter/api_key/",
		"default//openrouter/api_key",
		"default/ai//api_key",
		"default/ai/openrouter/api\x00key",
		"default/ai/openrouter/\xff\xfe",
		"a/b",
		"a/b/c/d/e",
		"personal:.api_key",
		"personal:openrouter.",
		"openrouter:noDotHere",
		"openrouter",
		".api_key",
		"openrouter.",
	}
	for _, in := range cases {
		got, err := vpath.Canonicalize(in, defaultDefaults, defaultResolver)
		if !errors.Is(err, vpath.ErrInvalidPath) {
			t.Errorf("Canonicalize(%q) = %q, %v; want ErrInvalidPath", in, got, err)
		}
	}
}

func TestCanonicalize_ResolverFailuresFailClosed(t *testing.T) {
	calls := 0
	flaky := func(p string) (string, error) {
		calls++
		if calls == 1 {
			return "ai", nil
		}
		return "", vpath.ErrUnknownProvider
	}
	if _, err := vpath.Canonicalize("openrouter:acme.api_key", defaultDefaults, flaky); !errors.Is(err, vpath.ErrUnknownProvider) {
		t.Fatalf("second resolve failure: got %v", err)
	}

	empty := func(string) (string, error) { return "", nil }
	if _, err := vpath.Canonicalize("openrouter.api_key", defaultDefaults, empty); !errors.Is(err, vpath.ErrInvalidPath) {
		t.Fatalf("empty category: got %v", err)
	}
}

func TestCanonicalize_ProviderAccountNeedsNamespace(t *testing.T) {
	_, err := vpath.Canonicalize("sentry:acme.auth_token", vpath.Defaults{}, defaultResolver)
	if !errors.Is(err, vpath.ErrAmbiguous) {
		t.Fatalf("want ErrAmbiguous, got %v", err)
	}
	got, err := vpath.Canonicalize("sentry:acme.auth_token", defaultDefaults, defaultResolver)
	if err != nil || got != "default/observability/sentry:acme/auth_token" {
		t.Fatalf("got %q, %v", got, err)
	}
	got, err = vpath.Canonicalize("team:sentry.auth_token", vpath.Defaults{}, defaultResolver)
	if err != nil || got != "team/observability/sentry/auth_token" {
		t.Fatalf("namespace override: got %q, %v", got, err)
	}
}

func TestParts_RejectsEmptyProviderOrAccount(t *testing.T) {
	for _, in := range []string{"ns/cat/:acct/field", "ns/cat/prov:/field"} {
		if _, err := vpath.Parts(in); !errors.Is(err, vpath.ErrInvalidPath) {
			t.Errorf("Parts(%q): got %v", in, err)
		}
	}
	p, err := vpath.Parts("ns/cat/prov:a:b/field")
	if err != nil {
		t.Fatal(err)
	}
	if p.Provider != "prov:a" || p.Account != "b" || p.Field != "field" {
		t.Fatalf("parts = %+v", p)
	}
}
