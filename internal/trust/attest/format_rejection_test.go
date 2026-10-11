package attest_test

import (
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/trust"
	"github.com/keylatch/keylatch/internal/trust/attest"
)

func TestFormatsRejectMissingEvidence(t *testing.T) {
	v := attest.New()
	for _, att := range []trust.Attestation{
		{Format: "fido-u2f"},
		{Format: "tpm"},
		{Format: "pkcs11", Statement: []byte("s")},
		{Format: "apple", Statement: []byte("s")},
		{Format: "packed"},
	} {
		got, err := v.Verify(att)
		if !errors.Is(err, trust.ErrAttestationInvalid) {
			t.Errorf("%s: err = %v", att.Format, err)
		}
		if got.Trusted {
			t.Errorf("%s: rejected attestation reported trusted", att.Format)
		}
	}
}

func TestVaultTokenTrustedByPolicy(t *testing.T) {
	got, err := attest.New().Verify(trust.Attestation{Format: "vault-token"})
	if err != nil || !got.Trusted || got.Model != "vault-transit" {
		t.Fatalf("verdict = %+v, %v", got, err)
	}
}

func TestFIDOU2FWithoutCertificatesIsUntrusted(t *testing.T) {
	got, err := attest.New().Verify(trust.Attestation{Format: "fido-u2f", Statement: []byte("s"), AAGUID: "unknown-aaguid"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Trusted || got.AAGUID != "unknown-aaguid" || got.Model != "" {
		t.Fatalf("verdict = %+v", got)
	}
}
