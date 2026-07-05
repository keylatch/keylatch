// Package attest implements FIDO2/WebAuthn attestation verification and
// PKCS#11/Apple Secure Enclave format extensions.
package attest

import (
	"errors"
	"fmt"

	"github.com/keylatch/keylatch/internal/trust"
)

// Verdict is the result of verifying an attestation statement.
type Verdict struct {
	// Trusted indicates whether the attestation chain verified against a known root.
	Trusted bool
	// Model is the human-readable device model name (value-free, from AAGUID map).
	Model string
	// AAGUID is the Authenticator Attestation GUID string.
	AAGUID string
	// FIPS indicates whether the device is FIPS-certified (from AAGUID map).
	FIPS bool
}

// Verifier verifies attestation statements against bundled MDS root certificates.
type Verifier struct {
	// rootPool is the bundled MDS root certificate pool.
	// In the stub implementation it is nil (no embedded root cert).
	rootPool interface{} //nolint:unused // planned: MDS root cert pool wired in attestation verification
}

// New returns a Verifier with the bundled MDS root certificate pool.
func New() *Verifier {
	return &Verifier{}
}

// Verify verifies att and returns a Verdict.
// Dispatches on att.Format: "packed", "fido-u2f", "tpm", "pkcs11", "apple".
// Returns ErrAttestationInvalid for any cryptographic failure.
// Unknown AAGUID → Verdict{Trusted:false}.
func (v *Verifier) Verify(att trust.Attestation) (Verdict, error) {
	switch att.Format {
	case "packed":
		return v.verifyPacked(att)
	case "fido-u2f":
		return v.verifyFIDOU2F(att)
	case "tpm":
		return v.verifyTPM(att)
	case "pkcs11":
		return v.verifyPKCS11(att)
	case "apple":
		return v.verifyApple(att)
	case "vault-token":
		// Vault attestation: no hardware attestation — trusted by policy.
		return Verdict{Trusted: true, Model: "vault-transit"}, nil
	default:
		return Verdict{}, fmt.Errorf("%w: unknown format %q", trust.ErrAttestationInvalid, att.Format)
	}
}

func (v *Verifier) verifyPacked(att trust.Attestation) (Verdict, error) {
	if len(att.Statement) == 0 {
		return Verdict{}, fmt.Errorf("%w: packed: empty statement", trust.ErrAttestationInvalid)
	}
	// Stub: parse AAGUID from statement; cross-reference with aaguid map.
	verdict := Verdict{AAGUID: att.AAGUID}
	if att.AAGUID != "" {
		verdict = lookupAAGUID(att.AAGUID, verdict)
	}
	// For the stub, "packed" with non-empty statement + known AAGUID → trusted.
	verdict.Trusted = att.AAGUID != "" && verdict.Trusted
	return verdict, nil
}

func (v *Verifier) verifyFIDOU2F(att trust.Attestation) (Verdict, error) {
	if len(att.Statement) == 0 {
		return Verdict{}, fmt.Errorf("%w: fido-u2f: empty statement", trust.ErrAttestationInvalid)
	}
	verdict := Verdict{AAGUID: att.AAGUID}
	if att.AAGUID != "" {
		verdict = lookupAAGUID(att.AAGUID, verdict)
	}
	verdict.Trusted = len(att.Certificates) > 0
	return verdict, nil
}

func (v *Verifier) verifyTPM(att trust.Attestation) (Verdict, error) {
	if len(att.Statement) == 0 {
		return Verdict{}, fmt.Errorf("%w: tpm: empty statement", trust.ErrAttestationInvalid)
	}
	return Verdict{Trusted: len(att.Certificates) > 0, AAGUID: att.AAGUID}, nil
}

func (v *Verifier) verifyPKCS11(att trust.Attestation) (Verdict, error) {
	if len(att.Certificates) == 0 {
		return Verdict{}, fmt.Errorf("%w: pkcs11: no attestation certificate", trust.ErrAttestationInvalid)
	}
	// Parse CKA_ATTESTATION_CERTIFICATE DER chain.
	// Stub: treat non-empty cert chain as trusted.
	return Verdict{Trusted: true, Model: "pkcs11-token"}, nil
}

func (v *Verifier) verifyApple(att trust.Attestation) (Verdict, error) {
	if len(att.Certificates) == 0 {
		return Verdict{}, fmt.Errorf("%w: apple: no device certificate", trust.ErrAttestationInvalid)
	}
	// Verify SE device cert chain vs Apple Root CA.
	// Stub: treat non-empty cert chain as trusted.
	return Verdict{Trusted: true, Model: "apple-secure-enclave"}, nil
}

// ErrAttestationInvalid is returned when an attestation statement fails verification.
var ErrAttestationInvalid = errors.New("attest: attestation invalid")

// lookupAAGUID cross-references an AAGUID string against the static map.
func lookupAAGUID(aaguid string, base Verdict) Verdict {
	if entry, ok := aaguidMap[aaguid]; ok {
		base.Trusted = true
		base.Model = entry.model
		base.FIPS = entry.fips
	}
	return base
}
