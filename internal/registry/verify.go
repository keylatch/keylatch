package registry

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/policy"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigsig "github.com/sigstore/sigstore/pkg/signature"
)

// registryCosignIdentityRegexp is the expected OIDC signing identity for
// keyless-signed provider template bundles published via publish-registry.yml.
const registryCosignIdentityRegexp = "https://github.com/keylatch/keylatch/.github/workflows/publish-registry.yml@refs/heads/main"

// registryCosignOIDCIssuer is the Sigstore OIDC issuer for GitHub Actions.
const registryCosignOIDCIssuer = "https://token.actions.githubusercontent.com"

// bundleVerifyKeyPEM is the Keylatch bundle signing public key (EC P-256).
// Loaded at build time via go:embed from the committed cosign.pub file.
// In tests, replace this variable with a generated test key.
//
//go:embed cosign.pub
var bundleVerifyKeyPEM []byte

// ErrUnsignedRegistryBundle is returned when a community bundle has no valid signature.
var ErrUnsignedRegistryBundle = errors.New("registry: bundle has no valid cosign signature")

// ErrCosignNotFound is returned when the cosign binary is not present on PATH.
// Callers can use errors.Is(err, ErrCosignNotFound) to distinguish a missing
// installation from an actual signature verification failure.
var ErrCosignNotFound = errors.New("registry: cosign binary not found on PATH")

// ErrSecurityBlock is returned when a restricted operation is attempted inside an LLM session.
var ErrSecurityBlock = errors.New("registry: operation blocked inside LLM session")

// BundleOpts controls bundle loading behaviour.
type BundleOpts struct {
	// AllowUnsigned permits loading an unsigned bundle.
	// This is blocked inside an LLM session unconditionally.
	AllowUnsigned bool

	// SigningIdentity is the expected cosign signing identity (email/OIDC issuer).
	SigningIdentity string
}

// Bundle is the result of a successfully loaded community provider bundle.
type Bundle struct {
	Templates []ConnectionTemplate
	Accessor  string // HMAC-based opaque reference for audit logs
	Signed    bool   // true if cosign verification passed
}

// SignatureStatus describes the outcome of bundle signature verification.
type SignatureStatus string

const (
	SignatureVerified SignatureStatus = "verified"
	SignatureUnsigned SignatureStatus = "unsigned"
	SignatureMismatch SignatureStatus = "mismatch"
)

// ActionRegistryLoad is the audit action name for bundle loading.
// Emitted on every bundle load attempt via RegistryLoadHook.
const ActionRegistryLoad = "registry_load"

// RegistryLoadAuditEvent carries the metadata emitted for each bundle load.
type RegistryLoadAuditEvent struct {
	Action          string          `json:"action"`
	BundleAccessor  string          `json:"bundle_accessor"` // HMAC of bundle path — never the path itself
	SignatureStatus SignatureStatus `json:"signature_status"`
	Time            time.Time       `json:"time"`
}

// RegistryLoadHook is called after every LoadBundle attempt.
// A future version replaces this with the real audit writer.
var RegistryLoadHook func(e RegistryLoadAuditEvent) = func(_ RegistryLoadAuditEvent) {}

// LoadBundle loads a community provider bundle from path.
//
// Security invariants:
//   - The bundle file must have an adjacent .sig file for cosign verification.
//   - AllowUnsigned=true is blocked inside LLM sessions (returns ErrSecurityBlock).
//   - An unsigned bundle with AllowUnsigned=false returns ErrUnsignedRegistryBundle.
//   - A tampered bundle (signature mismatch) returns ErrUnsignedRegistryBundle.
func LoadBundle(path string, opts BundleOpts) (Bundle, error) {
	// Gate AllowUnsigned on !IsLLMSession()
	if opts.AllowUnsigned && llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
		return Bundle{}, ErrSecurityBlock
	}

	// Read bundle file.
	data, err := os.ReadFile(path)
	if err != nil {
		return Bundle{}, fmt.Errorf("registry: read bundle: %w", err)
	}
	if bytes.Contains(data, []byte("TODO")) {
		return Bundle{}, fmt.Errorf("registry: bundle at %s contains TODO placeholder: all fields must be filled", path)
	}

	// Compute HMAC accessor for audit log (never log the path itself).
	accessor := bundleAccessor(path)

	// Check for signature file.
	sigPath := path + ".sig"
	sigData, sigErr := os.ReadFile(sigPath)
	if sigErr != nil {
		// No signature file found.
		status := SignatureUnsigned
		emitRegistryLoadAudit(accessor, status)
		if !opts.AllowUnsigned {
			return Bundle{}, ErrUnsignedRegistryBundle
		}
		// AllowUnsigned=true and not in LLM session — load without verification.
		return parseBundleData(data, accessor, false)
	}

	// Check for certificate file — presence indicates a keyless-signed bundle.
	certPath := path + ".cert"
	certData, certErr := os.ReadFile(certPath)

	var verifyErr error
	if certErr == nil && len(certData) > 0 {
		// Keyless path: certificate present — verify via subprocess (cosign verify-blob).
		verifyErr = verifyKeylessSignature(path, sigPath, certPath)
	} else {
		// Keyed path: no certificate — verify against embedded public key.
		verifyErr = verifyCosignSignature(data, sigData, opts.SigningIdentity)
	}

	if verifyErr != nil {
		emitRegistryLoadAudit(accessor, SignatureMismatch)
		return Bundle{}, fmt.Errorf("%w: %v", ErrUnsignedRegistryBundle, verifyErr)
	}

	emitRegistryLoadAudit(accessor, SignatureVerified)
	return parseBundleData(data, accessor, true)
}

// parseBundleData decodes the bundle JSON and returns a Bundle.
// Validates runtime modes in all community bundle templates.
func parseBundleData(data []byte, accessor string, signed bool) (Bundle, error) {
	var templates []ConnectionTemplate
	if err := json.Unmarshal(data, &templates); err != nil {
		return Bundle{}, fmt.Errorf("registry: parse bundle: %w", err)
	}
	// Validate runtime modes in every template.
	for i, tmpl := range templates {
		if tmpl.RuntimeSupport.Preferred != "" {
			if err := policy.ValidateRuntimeMode(string(tmpl.RuntimeSupport.Preferred)); err != nil {
				return Bundle{}, fmt.Errorf("bundle template %d: invalid preferred runtime: %w", i, err)
			}
		}
		for j, s := range tmpl.RuntimeSupport.Supported {
			if err := policy.ValidateRuntimeMode(string(s)); err != nil {
				return Bundle{}, fmt.Errorf("bundle template %d supported[%d]: invalid runtime: %w", i, j, err)
			}
		}
	}
	return Bundle{
		Templates: templates,
		Accessor:  accessor,
		Signed:    signed,
	}, nil
}

// bundleAccessor computes an HMAC-based opaque reference for audit logs.
// This prevents the bundle path (which may contain PII or sensitive directories) from appearing in logs.
func bundleAccessor(path string) string {
	// Use a random per-process nonce as the HMAC key.
	// For a deterministic audit reference, we use just the base filename.
	// The nonce is regenerated per process to prevent cross-process path correlation.
	mac := hmac.New(sha256.New, bundleHMACKey)
	mac.Write([]byte(filepath.Base(path)))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

// bundleHMACKey is a per-process random key for bundle accessors.
var bundleHMACKey = func() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic("registry: failed to generate HMAC key: " + err.Error())
	}
	return k
}()

// emitRegistryLoadAudit fires the RegistryLoadHook.
func emitRegistryLoadAudit(accessor string, status SignatureStatus) {
	RegistryLoadHook(RegistryLoadAuditEvent{
		Action:          ActionRegistryLoad,
		BundleAccessor:  accessor,
		SignatureStatus: status,
		Time:            time.Now(),
	})
}

// verifyCosignSignature verifies that sigData is a valid cosign signature over data.
//
// sigData: base64-encoded ECDSA-P256 signature produced by `cosign sign-blob`.
// data: raw bundle file bytes.
// signingIdentity: unused for keyed verification; reserved for future OIDC keyless.
//
// Uses the Keylatch bundle signing public key embedded from cosign.pub.
func verifyCosignSignature(data, sigData []byte, _ string) error {
	pub, err := cryptoutils.UnmarshalPEMToPublicKey(bundleVerifyKeyPEM)
	if err != nil {
		return fmt.Errorf("registry: load bundle signing key: %w", err)
	}
	verifier, err := sigsig.LoadVerifier(pub, crypto.SHA256)
	if err != nil {
		return fmt.Errorf("registry: construct verifier: %w", err)
	}
	if err := verifier.VerifySignature(bytes.NewReader(sigData), bytes.NewReader(data)); err == nil {
		return nil
	}
	trimmed := strings.TrimSpace(string(sigData))
	if rawSig, decErr := base64.StdEncoding.DecodeString(trimmed); decErr == nil {
		if err := verifier.VerifySignature(bytes.NewReader(rawSig), bytes.NewReader(data)); err == nil {
			return nil
		}
	}
	if rawSig, decErr := base64.RawStdEncoding.DecodeString(trimmed); decErr == nil {
		if err := verifier.VerifySignature(bytes.NewReader(rawSig), bytes.NewReader(data)); err == nil {
			return nil
		}
	}
	return fmt.Errorf("registry: bundle signature invalid")
}

// verifyKeylessSignature verifies a keyless cosign signature using the cosign
// CLI subprocess. The bundle path, signature file, and Fulcio certificate file
// are passed directly; the expected OIDC identity and issuer are the package-level
// constants registryCosignIdentityRegexp and registryCosignOIDCIssuer.
//
// The subprocess approach is intentional: the cosign Go library's keyless
// verification path requires direct Rekor/Fulcio network calls that are
// environment-dependent. Delegating to the CLI keeps the verification
// behaviour consistent with what operators run manually.
//
// In tests, override verifyKeylessSignatureFn to mock the subprocess.
func verifyKeylessSignature(bundlePath, sigPath, certPath string) error {
	return verifyKeylessSignatureFn(bundlePath, sigPath, certPath)
}

// verifyKeylessSignatureFn is the implementation of verifyKeylessSignature.
// Tests replace this variable to avoid real cosign subprocess calls.
var verifyKeylessSignatureFn = defaultVerifyKeylessSignature

func defaultVerifyKeylessSignature(bundlePath, sigPath, certPath string) error {
	// Look up cosign on PATH.
	cosignBin, err := lookupCosign()
	if err != nil {
		return err
	}

	args := []string{
		"verify-blob",
		"--certificate", certPath,
		"--signature", sigPath,
		"--certificate-identity-regexp", registryCosignIdentityRegexp,
		"--certificate-oidc-issuer", registryCosignOIDCIssuer,
		bundlePath,
	}

	out, err := runCommand(cosignBin, args...)
	if err != nil {
		return fmt.Errorf("registry: keyless verify failed: %w\n%s", err, out)
	}
	return nil
}

// lookupCosign returns the path to the cosign binary, or ErrCosignNotFound if
// it is not present on PATH. Callers can use errors.Is to distinguish a missing
// installation from a signature mismatch.
func lookupCosign() (string, error) {
	if path, err := execLookPath("cosign"); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("%w — install from https://docs.sigstore.dev/cosign/installation/", ErrCosignNotFound)
}

// execLookPath is exec.LookPath; tests may replace it.
var execLookPath = func(name string) (string, error) {
	return execLookPathImpl(name)
}

// runCommand runs a command and returns combined output. Tests may replace this variable.
var runCommand = func(name string, args ...string) ([]byte, error) {
	return runCommandImpl(name, args...)
}

// execLookPathImpl is the real exec.LookPath.
func execLookPathImpl(name string) (string, error) {
	return exec.LookPath(name)
}

// runCommandImpl runs a command and returns combined stdout+stderr output.
func runCommandImpl(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...) //nolint:gosec // name is always "cosign" resolved via LookPath
	return cmd.CombinedOutput()
}
