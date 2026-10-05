package oidc_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/manifest"
)

// SSO is unavailable and not used for identity — this package has
// no production callers (CLI/API/MCP), only its own tests. This test pins
// that containment via the manifest so a future wiring change is caught
// here. The synthetic-login regression (oidc_authentication_security_test.go,
// tag securitysuite) documents that Login still manufactures a session
// without a real IdP exchange; that repair requirement is expansion work
// and intentionally stays failing until real OIDC verification exists.
func TestSecurityRegression_SSOUnavailable(t *testing.T) {
	if manifest.Current().Enabled("sso") {
		t.Fatal("sso is Supported — oidc.Login's synthetic session (see oidc_authentication_security_test.go) would become reachable")
	}
}
