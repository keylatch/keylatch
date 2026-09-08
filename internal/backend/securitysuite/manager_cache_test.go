//go:build securitysuite

package securitysuite

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/keeper"
	"github.com/keylatch/keylatch/internal/backend/protonpass"
)

type auditRunner struct{ body []byte }

func (r auditRunner) Run(context.Context, string, []string, []byte) ([]byte, []byte, int, error) {
	return append([]byte(nil), r.body...), nil, 0, nil
}
func (r auditRunner) RunEnv(c context.Context, b string, a []string, s []byte, _ []string) ([]byte, []byte, int, error) {
	return r.Run(c, b, a, s)
}

// KNOWN-FAILING (F09): Keeper/Proton Pass caches return a shared mutable
// byte slice, so wiping the caller's copy — required by the backend.Backend
// contract — corrupts the cached value for the next reader.
func TestSecurityRegression_F09_ManagerCacheSurvivesCallerWipe(t *testing.T) {
	k, err := keeper.Open(keeper.Options{Bin: "/fake/keeper", Runner: auditRunner{[]byte(`{"password":"synthetic-secret"}`)}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := protonpass.Open(protonpass.Options{Bin: "/fake/pass-cli", Runner: auditRunner{[]byte(`{"content":{"note":"synthetic-secret"}}`)}})
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range []backend.Backend{k, p} {
		t.Run(b.Name(), func(t *testing.T) {
			defer b.Close()
			first, _, err := b.Get(context.Background(), "default/ai/audit/api_key")
			if err != nil {
				t.Fatal(err)
			}
			for i := range first {
				first[i] = 0
			}
			second, _, err := b.Get(context.Background(), "default/ai/audit/api_key")
			if err != nil {
				t.Fatal(err)
			}
			if string(second) != "synthetic-secret" {
				t.Error("second read corrupted by required caller wipe")
			}
		})
	}
}
