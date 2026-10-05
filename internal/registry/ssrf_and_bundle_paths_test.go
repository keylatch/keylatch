package registry

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/keylatch/keylatch/internal/template"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateTemplateBaseURL_FailClosed(t *testing.T) {
	cases := []struct {
		provider, url, want string
	}{
		{"openai", "://bad", "invalid URL"},
		{"openai", "https:///v1", "empty host"},
		{"unknown-provider", "https://api.openai.com", "no allowlist entry"},
		{"openai", "https://evil.example/v1", "not in allowlist"},
		{"hashicorp-vault", "https://10.1.2.3:8200", "deny range"},
		{"hashicorp-vault", "https://169.254.169.254/latest", "deny range"},
		{"hashicorp-vault", "https://[::1]:8200", "deny range"},
		{"hashicorp-vault", "https://[fd00::1]:8200", "deny range"},
	}
	for _, tc := range cases {
		err := ValidateTemplateBaseURL(tc.provider, tc.url)
		require.Error(t, err, tc.url)
		assert.Contains(t, err.Error(), tc.want, tc.url)
	}
	err := ValidateTemplateBaseURL("hashicorp-vault", "https://10.0.0.1")
	assert.ErrorIs(t, err, ErrSSRFTargetForbidden)
}

func TestValidateTemplateBaseURL_PublicIPAllowed(t *testing.T) {
	require.NoError(t, ValidateTemplateBaseURL("hashicorp-vault", "https://203.0.113.10:8200"))
}

func TestValidateTemplateBaseURL_ResolvedLoopbackDenied(t *testing.T) {
	// localhost resolves via the hosts file, not the network.
	err := ValidateTemplateBaseURL("hashicorp-vault", "https://localhost:8200")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSSRFTargetForbidden)
}

func TestCheckIPAndHostInList(t *testing.T) {
	assert.NoError(t, checkIP(net.ParseIP("8.8.8.8")))
	for _, ip := range []string{"127.0.0.1", "192.168.1.1", "100.64.0.1", "224.0.0.1", "0.0.0.0", "172.20.0.1"} {
		assert.ErrorIs(t, checkIP(net.ParseIP(ip)), ErrSSRFTargetForbidden, ip)
	}
	assert.True(t, hostInList("b", []string{"a", "b"}))
	assert.False(t, hostInList("B", []string{"a", "b"}))
}

func mxBundle(t *testing.T, data string, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "bundle.json")
	require.NoError(t, os.WriteFile(p, []byte(data), 0o600))
	for suffix, body := range files {
		require.NoError(t, os.WriteFile(p+suffix, []byte(body), 0o600))
	}
	return p
}

func mxCaptureLoadEvents(t *testing.T) *[]RegistryLoadAuditEvent {
	t.Helper()
	orig := RegistryLoadHook
	events := &[]RegistryLoadAuditEvent{}
	RegistryLoadHook = func(e RegistryLoadAuditEvent) { *events = append(*events, e) }
	t.Cleanup(func() { RegistryLoadHook = orig })
	return events
}

func TestLoadBundle_RejectsBadInput(t *testing.T) {
	testutil.ClearLLMSessionEnv(t)

	_, err := LoadBundle(filepath.Join(t.TempDir(), "missing.json"), BundleOpts{AllowUnsigned: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read bundle")

	_, err = LoadBundle(mxBundle(t, `[{"provider":"TODO"}]`, nil), BundleOpts{AllowUnsigned: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TODO placeholder")

	_, err = LoadBundle(mxBundle(t, `{not json`, nil), BundleOpts{AllowUnsigned: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse bundle")

	_, err = LoadBundle(mxBundle(t, `[{"provider":"x","runtime_support":{"preferred":"direct_classic_sandboxed_v9"}}]`, nil), BundleOpts{AllowUnsigned: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid preferred runtime")

	_, err = LoadBundle(mxBundle(t, `[{"provider":"x","runtime_support":{"supported":["gateway_typed","nope"]}}]`, nil), BundleOpts{AllowUnsigned: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "supported[1]")
}

func TestLoadBundle_ForgedKeyedSignatureIsMismatch(t *testing.T) {
	testutil.ClearLLMSessionEnv(t)
	events := mxCaptureLoadEvents(t)
	// Unpadded base64 exercises every decoding fallback before rejection.
	forged := base64.RawStdEncoding.EncodeToString([]byte("not-a-real-signature-bytes"))
	p := mxBundle(t, `[]`, map[string]string{".sig": forged})

	_, err := LoadBundle(p, BundleOpts{AllowUnsigned: true})
	require.ErrorIs(t, err, ErrUnsignedRegistryBundle, "AllowUnsigned never accepts a bad signature")
	assert.Contains(t, err.Error(), "signature invalid")
	require.Len(t, *events, 1)
	assert.Equal(t, SignatureMismatch, (*events)[0].SignatureStatus)
	assert.NotContains(t, (*events)[0].BundleAccessor, "bundle.json", "audit never carries the path")
}

func TestKeylessVerify_SubprocessContract(t *testing.T) {
	origLook, origRun := execLookPath, runCommand
	t.Cleanup(func() { execLookPath, runCommand = origLook, origRun })

	execLookPath = func(string) (string, error) { return "", errors.New("missing") }
	err := defaultVerifyKeylessSignature("b", "b.sig", "b.cert")
	assert.ErrorIs(t, err, ErrCosignNotFound)

	var gotName string
	var gotArgs []string
	execLookPath = func(string) (string, error) { return "/opt/cosign", nil }
	runCommand = func(name string, args ...string) ([]byte, error) {
		gotName, gotArgs = name, args
		return []byte("verification output"), errors.New("exit status 1")
	}
	err = defaultVerifyKeylessSignature("b", "b.sig", "b.cert")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "keyless verify failed")
	assert.Equal(t, "/opt/cosign", gotName)
	joined := strings.Join(gotArgs, " ")
	assert.Contains(t, joined, "verify-blob --certificate b.cert --signature b.sig")
	assert.Contains(t, joined, "--certificate-identity-regexp "+registryCosignIdentityRegexp)
	assert.Equal(t, "b", gotArgs[len(gotArgs)-1])

	runCommand = func(string, ...string) ([]byte, error) { return nil, nil }
	assert.NoError(t, defaultVerifyKeylessSignature("b", "b.sig", "b.cert"))
}

func TestExecHelpers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	p, err := execLookPathImpl("sh")
	require.NoError(t, err)
	assert.True(t, filepath.IsAbs(p))
	out, err := runCommandImpl(p, "-c", "echo out; echo err 1>&2")
	require.NoError(t, err)
	assert.Contains(t, string(out), "out")
	assert.Contains(t, string(out), "err")
}

func TestRegister_DuplicateAndInvalidActions(t *testing.T) {
	require.NoError(t, Register(ConnectionTemplate{Provider: "mx-dup-provider", DisplayName: "One"}))
	require.NoError(t, Register(ConnectionTemplate{Provider: "mx-dup-provider", DisplayName: "One"}), "identical re-registration is idempotent")
	err := Register(ConnectionTemplate{Provider: "mx-dup-provider", DisplayName: "Two"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate provider slug")

	err = Register(ConnectionTemplate{Provider: "mx-bad-actions", Actions: map[string]template.Action{"x": {Method: "TRACE", Path: "/"}}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid actions")
	_, getErr := Get("mx-bad-actions")
	assert.Error(t, getErr, "rejected templates are not registered")
}

func TestValidateTemplateBytes_Errors(t *testing.T) {
	err := ValidateTemplateBytes([]byte("provider: TODO"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TODO placeholder")

	err = ValidateTemplateBytes([]byte("provider: [unclosed"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid YAML")

	err = ValidateTemplateBytes([]byte("provider: x\n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "schema validation")
}

func TestNormalizeYAML_NonStringKeys(t *testing.T) {
	in := map[any]any{1: []any{map[any]any{true: "v"}}, "k": "s"}
	out := normalizeYAML(in)
	assert.Equal(t, map[string]any{"1": []any{map[string]any{"true": "v"}}, "k": "s"}, out)
}

func TestLoaders_ErrorPaths(t *testing.T) {
	ctx := context.Background()
	_, err := (&EmbedLoader{FS: fstest.MapFS{"bad.yaml": {Data: []byte("provider: x\n")}}}).LoadAll(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `template "bad.yaml"`)

	got, err := (&EmbedLoader{FS: fstest.MapFS{"README.md": {Data: []byte("x")}}}).LoadAll(ctx)
	require.NoError(t, err)
	assert.Empty(t, got)

	got, err = (&FSLoader{Dir: filepath.Join(t.TempDir(), "absent")}).LoadAll(ctx)
	require.NoError(t, err, "a missing directory means no templates")
	assert.Empty(t, got)

	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))
	_, err = (&FSLoader{Dir: file}).LoadAll(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is not a directory")

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "unsigned.yaml"), []byte("provider: x\n"), 0o600))
	got, err = (&FSLoader{Dir: dir, RequireSig: true}).LoadAll(ctx)
	require.NoError(t, err)
	assert.Empty(t, got, "unsigned community templates are skipped, never loaded")

	_, err = (&FSLoader{Dir: dir}).LoadAll(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `template "unsigned.yaml"`)

	_, err = (&CompositeLoader{Loaders: []Loader{&FSLoader{Dir: file}}}).LoadAll(ctx)
	require.Error(t, err)
}
