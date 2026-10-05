package attest_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/manifest"
)

// Hardware attestation cannot authorize any action because nothing
// in the build calls attest.Verifier.Verify — this package has no
// production callers (only its own tests). This test pins that containment
// via the manifest so a future wiring change is caught here. The forged
// attestation regression (forged_attestation_security_test.go, tag
// securitysuite) documents the still-unfixed per-format certificate/
// signature verification itself; that repair requirement is expansion work
// and intentionally stays failing until the crypto chain is implemented.
func TestSecurityRegression_HardwareAttestationUnavailable(t *testing.T) {
	if manifest.Current().Enabled("hardware_attestation") {
		t.Fatal("hardware_attestation is Supported — attest.Verify's unfixed forged-input handling (see forged_attestation_security_test.go) would become reachable")
	}
}
