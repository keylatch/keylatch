//go:build securitysuite

// Requires the securitysuite build tag; excluded from the ordinary
// go test ./... run. Run with: go test -tags securitysuite ./...
package oidc

import (
	"context"
	"testing"
)

// KNOWN-FAILING: Login manufactures a valid session even when no
// OAuth provider is configured, instead of failing closed.
func TestSecurityRegression_OIDCRequiresAuthentication(t *testing.T) {
	s, e := Login(context.Background(), ProviderGoogle, LoginOpts{})
	if e == nil && ValidateSession(s) == nil {
		t.Fatal("empty OAuth configuration produces valid synthetic identity without authentication")
	}
}
