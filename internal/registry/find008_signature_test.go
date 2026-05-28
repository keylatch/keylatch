package registry

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testBundle returns a minimal bundle JSON for testing.
func testBundleJSON(t *testing.T) []byte {
	t.Helper()
	templates := []ConnectionTemplate{
		{
			Provider:       "test-provider",
			DisplayName:    "Test Provider",
			Category:       "test",
			AuthFlow:       AuthAPIKey,
			StoragePathTpl: "{{.Namespace}}/test/{{.Account}}",
			TrustLevel:     TrustVerifiedCommunity,
			SecretFields: []SecretField{
				{Name: "api_key", Required: true, Sensitive: true},
			},
			TestStrategy: TestStrategy{
				Kind:     "http_get",
				Endpoint: "https://example.com/api/v1/test",
			},
			RuntimeSupport: RuntimeSupport{
				Preferred: RuntimeGatewayTyped,
				Supported: []RuntimeMode{RuntimeGatewayTyped},
			},
		},
	}
	data, err := json.Marshal(templates)
	require.NoError(t, err)
	return data
}

// writeTempBundle writes bundle data to a temp dir and returns (bundlePath, cleanup).
func writeTempBundle(t *testing.T, data []byte, sigData []byte) string {
	t.Helper()
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "test.bundle.json")
	require.NoError(t, os.WriteFile(bundlePath, data, 0o600))
	if sigData != nil {
		sigPath := bundlePath + ".sig"
		require.NoError(t, os.WriteFile(sigPath, sigData, 0o600))
	}
	return bundlePath
}

// setupTestKey generates an in-memory ECDSA P-256 keypair for tests,
// overrides the package-level bundleVerifyKeyPEM, and returns a function
// that signs data the same way cosign sign-blob does.
func setupTestKey(t *testing.T) func(data []byte) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Marshal public key to PEM and override the package variable.
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	orig := bundleVerifyKeyPEM
	bundleVerifyKeyPEM = pubPEM
	t.Cleanup(func() { bundleVerifyKeyPEM = orig })

	// Return a signer that produces base64-encoded DER ECDSA signatures.
	return func(data []byte) []byte {
		digest := sha256.Sum256(data)
		sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
		if err != nil {
			panic("test sign: " + err.Error())
		}
		return []byte(base64.StdEncoding.EncodeToString(sig))
	}
}

// TestUnsignedBundleRejected verifies FIND-008: a bundle without a .sig file
// is rejected with ErrUnsignedRegistryBundle when AllowUnsigned=false.
func TestUnsignedBundleRejected(t *testing.T) {
	data := testBundleJSON(t)
	bundlePath := writeTempBundle(t, data, nil) // no sig file

	_, err := LoadBundle(bundlePath, BundleOpts{AllowUnsigned: false})
	assert.ErrorIs(t, err, ErrUnsignedRegistryBundle, "unsigned bundle must be rejected")
}

// TestTamperedBundleRejected verifies FIND-008: a bundle whose data has been
// modified after signing is rejected with ErrUnsignedRegistryBundle.
func TestTamperedBundleRejected(t *testing.T) {
	sign := setupTestKey(t)
	data := testBundleJSON(t)

	// Tamper with the bundle data after signing.
	var templates []ConnectionTemplate
	require.NoError(t, json.Unmarshal(data, &templates))
	templates[0].Redaction = append(templates[0].Redaction, RedactionRule{
		Pattern:     "TAMPERED",
		Replacement: "****",
	})
	tamperedData, err := json.Marshal(templates)
	require.NoError(t, err)

	// Sig is over original data, but we write tampered data → mismatch.
	bundlePath := writeTempBundle(t, tamperedData, sign(data))

	_, err = LoadBundle(bundlePath, BundleOpts{AllowUnsigned: false})
	assert.ErrorIs(t, err, ErrUnsignedRegistryBundle, "tampered bundle must be rejected")
}

// TestAllowUnsignedOutsideLLMSession verifies FIND-008: AllowUnsigned=true is
// accepted when not inside an LLM session.
func TestAllowUnsignedOutsideLLMSession(t *testing.T) {
	// Ensure no LLM session signals are set.
	t.Setenv("CLAUDE_CODE", "")
	t.Setenv("CODEX_ENV", "")
	t.Setenv("CREDENTIALS_LLM_SESSION", "")

	data := testBundleJSON(t)
	bundlePath := writeTempBundle(t, data, nil) // no sig file

	bundle, err := LoadBundle(bundlePath, BundleOpts{AllowUnsigned: true})
	require.NoError(t, err, "AllowUnsigned=true outside LLM session must succeed")
	assert.False(t, bundle.Signed)
	assert.NotEmpty(t, bundle.Templates)
}

// TestAllowUnsignedBlockedInsideLLMSession verifies FIND-008: AllowUnsigned=true
// is blocked inside an LLM session.
func TestAllowUnsignedBlockedInsideLLMSession(t *testing.T) {
	// Simulate LLM session.
	t.Setenv("CLAUDE_CODE", "claude-code-v1")

	data := testBundleJSON(t)
	bundlePath := writeTempBundle(t, data, nil) // no sig file

	_, err := LoadBundle(bundlePath, BundleOpts{AllowUnsigned: true})
	assert.ErrorIs(t, err, ErrSecurityBlock,
		"AllowUnsigned=true inside LLM session must return ErrSecurityBlock")
}

// TestAuditLogContainsRegistryLoadAction verifies that the RegistryLoadHook is
// called with an ActionRegistryLoad event after each bundle load attempt.
func TestAuditLogContainsRegistryLoadAction(t *testing.T) {
	var events []RegistryLoadAuditEvent
	orig := RegistryLoadHook
	t.Cleanup(func() { RegistryLoadHook = orig })
	RegistryLoadHook = func(e RegistryLoadAuditEvent) {
		events = append(events, e)
	}

	// Ensure no LLM session signals are set.
	t.Setenv("CLAUDE_CODE", "")
	t.Setenv("CODEX_ENV", "")
	t.Setenv("CREDENTIALS_LLM_SESSION", "")

	sign := setupTestKey(t)
	data := testBundleJSON(t)

	// Attempt 1: unsigned bundle, AllowUnsigned=false → rejected but audit fires.
	bundlePath1 := writeTempBundle(t, data, nil)
	_, _ = LoadBundle(bundlePath1, BundleOpts{AllowUnsigned: false})

	// Attempt 2: properly signed bundle → SignatureVerified.
	bundlePath2 := writeTempBundle(t, data, sign(data))
	_, _ = LoadBundle(bundlePath2, BundleOpts{AllowUnsigned: false})

	require.Len(t, events, 2, "two load attempts must emit two audit events")

	assert.Equal(t, ActionRegistryLoad, events[0].Action)
	assert.Equal(t, SignatureUnsigned, events[0].SignatureStatus)
	assert.NotEmpty(t, events[0].BundleAccessor)

	assert.Equal(t, ActionRegistryLoad, events[1].Action)
	assert.Equal(t, SignatureVerified, events[1].SignatureStatus)
	assert.NotEmpty(t, events[1].BundleAccessor)
	assert.False(t, events[1].Time.IsZero())
}

// TestValidSignedBundleLoadsSuccessfully verifies FIND-008: a properly signed
// bundle loads without error when AllowUnsigned=false.
func TestValidSignedBundleLoadsSuccessfully(t *testing.T) {
	t.Setenv("CLAUDE_CODE", "")
	t.Setenv("CODEX_ENV", "")
	t.Setenv("CREDENTIALS_LLM_SESSION", "")

	sign := setupTestKey(t)
	data := testBundleJSON(t)
	bundlePath := writeTempBundle(t, data, sign(data))

	bundle, err := LoadBundle(bundlePath, BundleOpts{AllowUnsigned: false})
	require.NoError(t, err, "properly signed bundle must load")
	assert.True(t, bundle.Signed)
	assert.NotEmpty(t, bundle.Templates)
	assert.NotEmpty(t, bundle.Accessor)
}
