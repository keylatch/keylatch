package canary_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/canary"
)

func TestNewSetIsUniquePerSessionAndLooksLikeTheRealThing(t *testing.T) {
	a, err := canary.NewSet("stripe")
	if err != nil {
		t.Fatal(err)
	}
	b, err := canary.NewSet("stripe")
	if err != nil {
		t.Fatal(err)
	}
	if got := a.Env["KEYLATCH_CANARY_STRIPE"]; !strings.HasPrefix(got, "klc-canary-stripe-") {
		t.Errorf("env canary %q", got)
	}
	seen := map[string]bool{}
	for _, v := range append(append([]string{}, a.Values...), b.Values...) {
		if seen[v] {
			t.Errorf("value %q repeats across sessions", v)
		}
		seen[v] = true
	}
	files := map[string]string{}
	for _, f := range a.Files {
		files[f.Path] = f.Content
	}
	checks := map[string]*regexp.Regexp{
		".aws/credentials":     regexp.MustCompile(`aws_access_key_id = AK` + `IA[A-Z2-7]{16}\naws_secret_access_key = [A-Za-z0-9+/]{40}\n`),
		".config/gh/hosts.yml": regexp.MustCompile(`oauth_token: gh` + `p_[A-Za-z0-9]{36}\n`),
		".npmrc":               regexp.MustCompile(`_authToken=np` + `m_[A-Za-z0-9]{36}\n`),
	}
	for path, re := range checks {
		if !re.MatchString(files[path]) {
			t.Errorf("%s does not look like the real file:\n%s", path, files[path])
		}
	}
	for _, v := range a.Values {
		found := false
		for _, content := range files {
			found = found || strings.Contains(content, v)
		}
		if _, isEnv := map[string]bool{a.Env["KEYLATCH_CANARY_STRIPE"]: true}[v]; !found && !isEnv {
			t.Errorf("value %q is in no file", v)
		}
	}
}
