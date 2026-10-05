//go:build securitysuite

// Requires the "securitysuite" build tag; excluded from the ordinary
// `go test ./...` run because direct_brokered isn't reachable from any
// entry point yet. Run with: go test -tags securitysuite ./internal/runner/...
package runner_test

import (
	"context"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/broker"
	"github.com/keylatch/keylatch/internal/runner"
)

// KNOWN-FAILING: direct_brokered's --clean-env filtering runs after
// credential injection, so CleanBaseEnv strips the freshly issued ephemeral
// token because the injection rule's env var name is never added to
// CleanBaseEnv's extras.
func TestSecurityRegression_BrokerCleanEnvRetainsIssuedCredential(t *testing.T) {
	vault := newClassicMockBackend()
	path := classicSecretPath("default", "ai", "myapi", "api_key")
	if err := vault.Set(context.Background(), path, []byte("synthetic-root"), backend.Meta{}); err != nil {
		t.Fatal(err)
	}
	b := &stubBroker{result: broker.NewExchangeResult("myapi", "inject", time.Hour, broker.FreshExchange, []byte("synthetic-ephemeral"))}
	receipt, err := runner.NewBrokeredDriver(vault, b, nil).Run(context.Background(), runner.ExecRequest{
		ConnectionSlug: "myapi", CleanEnv: true, Command: []string{"sh", "-c", `test "$TEST_API_KEY" = synthetic-ephemeral`},
	}, brokeredTmpl("myapi"))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ExitCode != 0 {
		t.Error("clean environment removed newly issued credential")
	}
}
