package gateway

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/policy/connpolicy"
	"github.com/keylatch/keylatch/internal/policy/enforce"
)

type emptyVault struct{}

func (emptyVault) Get(context.Context, string) ([]byte, backend.Meta, error) {
	return nil, backend.Meta{}, backend.ErrNotFound
}

// The CLI's run path and the gateway ask the same enforcer, so one request
// gets one answer in both.
func TestCLIAndGatewayAgree(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	policyDir := filepath.Join(dir, "policy.d")

	doc, err := connpolicy.Parse([]byte(`{"schema_version": 2, "connection": "openrouter",
	  "callers": {"agent": {"allow": true, "runtimes": ["gateway_typed"]},
	              "human": {"allow": true}, "service": {"allow": true, "runtimes": ["gateway_sdk"]}, "host": "deny"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := (connpolicy.Store{Dir: policyDir}).Replace(map[string]connpolicy.Document{"openrouter": doc}); err != nil {
		t.Fatal(err)
	}

	key := make([]byte, 32)
	_, _ = rand.Read(key)
	storePath := filepath.Join(dir, "tokens.json")
	srv, err := New(ServerOptions{
		Bind:           "127.0.0.1:0",
		SigningKey:     key,
		ApprovalsDir:   filepath.Join(dir, "approvals"),
		TokenStorePath: storePath,
		Env:            llmcontext.DefaultLookup,
		PolicyPath:     policyPath,
		Vault:          emptyVault{},
	})
	if err != nil {
		t.Fatal(err)
	}
	cli := &enforce.Enforcer{PolicyPath: policyPath, PolicyDir: policyDir}

	// Typed routes are served under gateway_typed. The service entry lists only
	// gateway_sdk, so a service is denied here by both sides.
	typedPath := "/api/openrouter/chat.completion"
	for _, tc := range []struct {
		caller  callerkind.Kind
		path    string
		runtime string
	}{
		{callerkind.Agent, typedPath, "gateway_typed"},
		{callerkind.Human, typedPath, "gateway_typed"},
		{callerkind.Service, typedPath, "gateway_typed"},
		{callerkind.Host, typedPath, "gateway_typed"},
	} {
		t.Run(string(tc.caller)+" "+tc.runtime, func(t *testing.T) {
			rt, ok := srv.router.Match(http.MethodPost, tc.path)
			if !ok {
				t.Fatalf("no route for %s", tc.path)
			}
			jwt, _, err := token.Mint(token.TokenSpec{
				Actor:        "actor",
				Capabilities: []string{"openrouter.*"},
				TTL:          time.Hour,
				Caller:       tc.caller,
				SigningKey:   key,
				StorePath:    storePath,
			})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer "+jwt)
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			srv.gatewayHandler(rr, req)

			gatewayDenied := rr.Code == http.StatusForbidden && strings.Contains(rr.Body.String(), "policy_denied")
			cliDecision := cli.Decide(context.Background(), enforce.Request{
				Connection: "openrouter",
				Action:     rt.Capability,
				Runtime:    tc.runtime,
				Caller:     tc.caller,
				Actor:      "actor",
			})
			if gatewayDenied == cliDecision.Allow {
				t.Fatalf("gateway denied=%v (status %d, %s), CLI allow=%v (%s)", gatewayDenied, rr.Code, rr.Body.String(), cliDecision.Allow, cliDecision.Reason)
			}
		})
	}
}
