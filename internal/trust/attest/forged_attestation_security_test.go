//go:build securitysuite

// Requires the securitysuite build tag; excluded from the ordinary
// go test ./... run. Run with: go test -tags securitysuite ./...
package attest

import (
	"testing"

	"github.com/keylatch/keylatch/internal/trust"
)

// KNOWN-FAILING (F40): Verify has no format-specific signature or
// certificate-chain checking, so an unsigned statement with garbage
// certificate bytes can still be reported as Trusted for every attestation
// format.
func TestSecurityRegression_F40_ForgedAttestation(t *testing.T) {
	for _, format := range []string{"apple", "pkcs11", "tpm", "fido-u2f"} {
		t.Run(format, func(t *testing.T) {
			v, e := New().Verify(trust.Attestation{Format: format, Statement: []byte("not signed"), Certificates: [][]byte{[]byte("not a certificate")}})
			if e == nil && v.Trusted {
				t.Fatal("unparseable certificate and unsigned statement marked trusted")
			}
		})
	}
}
