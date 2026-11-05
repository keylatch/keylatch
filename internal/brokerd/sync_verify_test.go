//go:build unix

package brokerd

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
	keysync "github.com/keylatch/keylatch/internal/sync"
)

func registerVerifyDemo(t *testing.T) {
	t.Helper()
	err := registry.Register(registry.ConnectionTemplate{
		Provider: "verify-demo", DisplayName: "Verify demo", Category: "ai",
		Hosts:        []string{"api.verify-demo.test", "*.svc.verify-demo.test"},
		SecretFields: []registry.SecretField{{Name: "api_key", Required: true, Sensitive: true}},
	})
	if err != nil && !strings.Contains(err.Error(), "already") {
		t.Fatal(err)
	}
}

func verifyManifest(t *testing.T, conn, url string) keysync.Manifest {
	t.Helper()
	m, err := keysync.Parse([]byte(`version: 1
targets:
  local: {type: env-file, path: .env.local}
vars:
  - name: API_KEY
    from: {connection: `+conn+`, field: api_key}
    to: {local: [file]}
    verify: {url: `+url+`}
`), nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestVerifyURLMustBeOneOfTheSourceHosts(t *testing.T) {
	registerVerifyDemo(t)
	for _, ok := range []string{
		"https://api.verify-demo.test/v1/me",
		"https://API.verify-demo.test:443/v1/me",
		"https://eu.svc.verify-demo.test/",
	} {
		if _, err := verifyAllowlist(verifyManifest(t, "verify-demo", ok)); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"https://evil.test/",
		"https://api.verify-demo.test.evil.test/",
		"https://svc.verify-demo.test/",
		"https://api.verify-demo.test:8443/",
		"https://user:pw@api.verify-demo.test/",
	} {
		if _, err := verifyAllowlist(verifyManifest(t, "verify-demo", bad)); err == nil {
			t.Errorf("%s was allowed", bad)
		}
	}
	if _, err := verifyAllowlist(verifyManifest(t, "no-such-connection", "https://api.verify-demo.test/")); err == nil {
		t.Error("a source with no known hosts was allowed")
	}
	none, err := keysync.Parse([]byte(syncManifest), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := verifyAllowlist(none); err != nil || len(got) != 0 {
		t.Errorf("no verify = %v %v", got, err)
	}
}

func TestGuardedProbeSendsTheValueOnlyToAllowedHosts(t *testing.T) {
	registerVerifyDemo(t)
	var sent []string
	probe := func(_ context.Context, url string, _ []byte) error { sent = append(sent, url); return nil }
	good := "https://api.verify-demo.test/v1/me"
	allowed, err := verifyAllowlist(verifyManifest(t, "verify-demo", good))
	if err != nil {
		t.Fatal(err)
	}
	guarded := guardProbe(allowed, probe)
	if err := guarded(context.Background(), good, []byte("v")); err != nil {
		t.Fatal(err)
	}
	if err := guarded(context.Background(), "https://evil.test/", []byte("v")); err == nil {
		t.Fatal("a URL outside the manifest was probed")
	}
	if len(sent) != 1 || sent[0] != good {
		t.Fatalf("probed %v", sent)
	}
	failing := guardProbe(allowed, func(context.Context, string, []byte) error { return errors.New("down") })
	if err := failing(context.Background(), good, []byte("v")); err == nil {
		t.Fatal("a probe failure was hidden")
	}
}
