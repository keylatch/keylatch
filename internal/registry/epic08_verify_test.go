package registry

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeTempBundleWithCert writes bundle data, signature, and an optional
// certificate file to a temp dir. certData=nil means no .cert file is written.
func writeTempBundleWithCert(t *testing.T, data []byte, sigData []byte, certData []byte) string {
	t.Helper()
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "test.bundle.json")
	require.NoError(t, os.WriteFile(bundlePath, data, 0o600))
	if sigData != nil {
		require.NoError(t, os.WriteFile(bundlePath+".sig", sigData, 0o600))
	}
	if certData != nil {
		require.NoError(t, os.WriteFile(bundlePath+".cert", certData, 0o600))
	}
	return bundlePath
}

// stubKeylessVerify replaces verifyKeylessSignatureFn with a stub that either
// succeeds or returns an error, restoring the original on cleanup.
func stubKeylessVerify(t *testing.T, returnErr error) {
	t.Helper()
	orig := verifyKeylessSignatureFn
	t.Cleanup(func() { verifyKeylessSignatureFn = orig })
	verifyKeylessSignatureFn = func(_, _, _ string) error {
		return returnErr
	}
}

// TestRegistryVerify_Keyless verifies that a bundle with both .sig and .cert
// files routes to the keyless verification path.
func TestRegistryVerify_Keyless(t *testing.T) {
	// Clear LLM session signals.
	t.Setenv("CLAUDE_CODE", "")
	t.Setenv("CODEX_ENV", "")
	t.Setenv("CREDENTIALS_LLM_SESSION", "")

	// Stub keyless verifier to succeed.
	stubKeylessVerify(t, nil)

	data := testBundleJSON(t)
	// .sig and .cert present — keyless path.
	bundlePath := writeTempBundleWithCert(t, data,
		[]byte("stub-sig"),
		[]byte("stub-cert"),
	)

	bundle, err := LoadBundle(bundlePath, BundleOpts{AllowUnsigned: false})
	require.NoError(t, err, "keyless-signed bundle must load successfully")
	assert.True(t, bundle.Signed, "bundle.Signed must be true after keyless verification")
	assert.NotEmpty(t, bundle.Templates)
}

// TestRegistryVerify_Keyless_Failure verifies that a keyless verification
// failure maps to ErrUnsignedRegistryBundle.
func TestRegistryVerify_Keyless_Failure(t *testing.T) {
	t.Setenv("CLAUDE_CODE", "")
	t.Setenv("CODEX_ENV", "")
	t.Setenv("CREDENTIALS_LLM_SESSION", "")

	// Stub keyless verifier to fail.
	stubKeylessVerify(t, fmt.Errorf("certificate expired"))

	data := testBundleJSON(t)
	bundlePath := writeTempBundleWithCert(t, data,
		[]byte("stub-sig"),
		[]byte("stub-cert"),
	)

	_, err := LoadBundle(bundlePath, BundleOpts{AllowUnsigned: false})
	assert.ErrorIs(t, err, ErrUnsignedRegistryBundle,
		"keyless verification failure must return ErrUnsignedRegistryBundle")
}

// TestRegistryVerify_Keyed verifies that a bundle with only a .sig file (no .cert)
// routes to the keyed ECDSA-P256 verification path.
func TestRegistryVerify_Keyed(t *testing.T) {
	t.Setenv("CLAUDE_CODE", "")
	t.Setenv("CODEX_ENV", "")
	t.Setenv("CREDENTIALS_LLM_SESSION", "")

	sign := setupTestKey(t)
	data := testBundleJSON(t)

	// Only .sig, no .cert — keyed path.
	bundlePath := writeTempBundleWithCert(t, data, sign(data), nil)

	bundle, err := LoadBundle(bundlePath, BundleOpts{AllowUnsigned: false})
	require.NoError(t, err, "keyed-signed bundle must load successfully")
	assert.True(t, bundle.Signed, "bundle.Signed must be true after keyed verification")
	assert.NotEmpty(t, bundle.Templates)
}

// TestRegistryVerify_Keyed_EmptyCert verifies that an empty .cert file (zero bytes)
// routes to the keyed verification path, not keyless. An empty cert file is not
// treated as a keyless bundle.
func TestRegistryVerify_Keyed_EmptyCert(t *testing.T) {
	t.Setenv("CLAUDE_CODE", "")
	t.Setenv("CODEX_ENV", "")
	t.Setenv("CREDENTIALS_LLM_SESSION", "")

	sign := setupTestKey(t)
	data := testBundleJSON(t)

	// .cert exists but is empty — should fall through to keyed path.
	bundlePath := writeTempBundleWithCert(t, data, sign(data), []byte(""))

	bundle, err := LoadBundle(bundlePath, BundleOpts{AllowUnsigned: false})
	require.NoError(t, err, "keyed bundle with empty .cert file must load successfully")
	assert.True(t, bundle.Signed)
}

// TestRegistryVerify_NoSigFile_Fails verifies that a bundle with no .sig file at all
// is rejected with ErrUnsignedRegistryBundle regardless of AllowUnsigned setting
// (when AllowUnsigned=false).
func TestRegistryVerify_NoSigFile_Fails(t *testing.T) {
	t.Setenv("CLAUDE_CODE", "")
	t.Setenv("CODEX_ENV", "")
	t.Setenv("CREDENTIALS_LLM_SESSION", "")

	data := testBundleJSON(t)
	// No .sig, no .cert.
	bundlePath := writeTempBundleWithCert(t, data, nil, nil)

	_, err := LoadBundle(bundlePath, BundleOpts{AllowUnsigned: false})
	assert.ErrorIs(t, err, ErrUnsignedRegistryBundle,
		"bundle with no .sig file must be rejected with ErrUnsignedRegistryBundle")
}

// TestRegistryVerify_NoSigFile_AllowUnsigned verifies that a bundle without a
// .sig file loads successfully when AllowUnsigned is true and we are not inside
// an LLM session.
func TestRegistryVerify_NoSigFile_AllowUnsigned(t *testing.T) {
	t.Setenv("CLAUDE_CODE", "")
	t.Setenv("CODEX_ENV", "")
	t.Setenv("CREDENTIALS_LLM_SESSION", "")

	data := testBundleJSON(t)
	// No .sig, no .cert.
	bundlePath := writeTempBundleWithCert(t, data, nil, nil)

	bundle, err := LoadBundle(bundlePath, BundleOpts{AllowUnsigned: true})
	require.NoError(t, err, "unsigned bundle must load when AllowUnsigned=true outside an LLM session")
	assert.False(t, bundle.Signed, "bundle.Signed must be false for an unsigned bundle")
	assert.NotEmpty(t, bundle.Templates)
}

// TestRegistryVerify_KeylessAuditEvent verifies that keyless verification emits
// a SignatureVerified audit event.
func TestRegistryVerify_KeylessAuditEvent(t *testing.T) {
	t.Setenv("CLAUDE_CODE", "")
	t.Setenv("CODEX_ENV", "")
	t.Setenv("CREDENTIALS_LLM_SESSION", "")

	var events []RegistryLoadAuditEvent
	orig := RegistryLoadHook
	t.Cleanup(func() { RegistryLoadHook = orig })
	RegistryLoadHook = func(e RegistryLoadAuditEvent) { events = append(events, e) }

	stubKeylessVerify(t, nil)

	data := testBundleJSON(t)
	bundlePath := writeTempBundleWithCert(t, data, []byte("stub-sig"), []byte("stub-cert"))

	_, err := LoadBundle(bundlePath, BundleOpts{AllowUnsigned: false})
	require.NoError(t, err)

	require.Len(t, events, 1)
	assert.Equal(t, SignatureVerified, events[0].SignatureStatus)
	assert.Equal(t, ActionRegistryLoad, events[0].Action)
}

// TestRegistryVerify_KeylessIdentityConstants checks that the package-level OIDC
// identity and issuer constants match the expected production values.
func TestRegistryVerify_KeylessIdentityConstants(t *testing.T) {
	assert.Equal(t,
		"https://github.com/keylatch/keylatch/.github/workflows/publish-registry.yml@refs/heads/main",
		registryCosignIdentityRegexp,
	)
	assert.Equal(t,
		"https://token.actions.githubusercontent.com",
		registryCosignOIDCIssuer,
	)
}
