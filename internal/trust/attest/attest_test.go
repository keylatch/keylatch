package attest_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/trust"
	"github.com/keylatch/keylatch/internal/trust/attest"
)

func TestVerify_Packed_KnownAAGUID(t *testing.T) {
	v := attest.New()
	att := trust.Attestation{
		Format:    "packed",
		Statement: []byte(`{"alg": -7}`),
		AAGUID:    "2fc0579f-8113-47ea-b116-bb5a8db9202a", // YubiKey 5 NFC
	}
	verdict, err := v.Verify(att)
	if err != nil {
		t.Fatalf("Verify(packed, known AAGUID): %v", err)
	}
	if !verdict.Trusted {
		t.Error("expected Trusted=true for known YubiKey AAGUID")
	}
	if verdict.Model != "YubiKey 5 NFC" {
		t.Errorf("Model = %q, want %q", verdict.Model, "YubiKey 5 NFC")
	}
}

func TestVerify_Packed_UnknownAAGUID(t *testing.T) {
	v := attest.New()
	att := trust.Attestation{
		Format:    "packed",
		Statement: []byte(`{"alg":-7}`),
		AAGUID:    "ffffffff-ffff-ffff-ffff-ffffffffffff",
	}
	verdict, err := v.Verify(att)
	if err != nil {
		t.Fatalf("Verify(packed, unknown AAGUID): %v", err)
	}
	if verdict.Trusted {
		t.Error("expected Trusted=false for unknown AAGUID")
	}
}

func TestVerify_FIDOU2F(t *testing.T) {
	v := attest.New()
	att := trust.Attestation{
		Format:       "fido-u2f",
		Statement:    []byte(`{"sig":"deadbeef"}`),
		Certificates: [][]byte{[]byte("cert1")},
	}
	verdict, err := v.Verify(att)
	if err != nil {
		t.Fatalf("Verify(fido-u2f): %v", err)
	}
	if !verdict.Trusted {
		t.Error("fido-u2f with certificate: expected Trusted=true")
	}
}

func TestVerify_TPM(t *testing.T) {
	v := attest.New()
	att := trust.Attestation{
		Format:       "tpm",
		Statement:    []byte(`{"ver":"2.0"}`),
		Certificates: [][]byte{[]byte("aik-cert")},
	}
	verdict, err := v.Verify(att)
	if err != nil {
		t.Fatalf("Verify(tpm): %v", err)
	}
	if !verdict.Trusted {
		t.Error("tpm with certificate: expected Trusted=true")
	}
}

func TestVerify_TamperedStatement(t *testing.T) {
	v := attest.New()
	att := trust.Attestation{
		Format:    "packed",
		Statement: nil, // empty = tampered/missing
	}
	_, err := v.Verify(att)
	if err == nil {
		t.Error("expected error for empty packed statement, got nil")
	}
}

func TestVerify_UnknownFormat(t *testing.T) {
	v := attest.New()
	att := trust.Attestation{
		Format:    "unknown_format",
		Statement: []byte("data"),
	}
	_, err := v.Verify(att)
	if err == nil {
		t.Error("expected error for unknown format, got nil")
	}
}

func TestVerify_PKCS11(t *testing.T) {
	v := attest.New()
	att := trust.Attestation{
		Format:       "pkcs11",
		Certificates: [][]byte{[]byte("ckattr-cert-der")},
	}
	verdict, err := v.Verify(att)
	if err != nil {
		t.Fatalf("Verify(pkcs11): %v", err)
	}
	if !verdict.Trusted {
		t.Error("pkcs11 with certificate: expected Trusted=true")
	}
}

func TestVerify_Apple(t *testing.T) {
	v := attest.New()
	att := trust.Attestation{
		Format:       "apple",
		Certificates: [][]byte{[]byte("device-cert-der")},
	}
	verdict, err := v.Verify(att)
	if err != nil {
		t.Fatalf("Verify(apple): %v", err)
	}
	if !verdict.Trusted {
		t.Error("apple with certificate: expected Trusted=true")
	}
}

func TestVerify_FIPS_Detection(t *testing.T) {
	v := attest.New()
	att := trust.Attestation{
		Format:    "packed",
		Statement: []byte(`{"alg":-8}`),
		AAGUID:    "73bb0cd4-e502-49b8-9c6f-b59445bf720b", // YubiKey 5 NFC FIPS
	}
	verdict, err := v.Verify(att)
	if err != nil {
		t.Fatalf("Verify(fips): %v", err)
	}
	if !verdict.FIPS {
		t.Error("FIPS YubiKey: expected FIPS=true")
	}
}
