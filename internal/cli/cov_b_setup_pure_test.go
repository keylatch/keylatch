package cli

// cov_b_setup_pure_test.go — Agent B coverage for pure/unit-testable functions in
// setup_cmd.go: validateURISegments, detectCLI, findExecutable, platformBackend.
// These are pure functions with no I/O side effects (except PATH lookups).
// Hermetic: no network, no OS keychain.

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// --- validateURISegments ---

func TestValidateURISegments_ValidSchemeSegments(t *testing.T) {
	cases := []string{
		"op://vault/item/field",
		"bw://myorg/login/password",
		"file://dir/item",
		"op://my-vault/my-item/my_field",
		"op://vault/item.with.dot/field",
		"op://vault/item123/field456",
	}
	for _, uri := range cases {
		if err := validateURISegments(uri); err != nil {
			t.Errorf("validateURISegments(%q): unexpected error: %v", uri, err)
		}
	}
}

func TestValidateURISegments_NoScheme(t *testing.T) {
	err := validateURISegments("vault/item/field")
	if err == nil {
		t.Fatal("expected error for URI without scheme")
	}
	if !strings.Contains(err.Error(), "no scheme separator") {
		t.Errorf("expected 'no scheme separator' in error, got: %v", err)
	}
}

func TestValidateURISegments_InvalidSegment_Spaces(t *testing.T) {
	err := validateURISegments("op://vault/item with spaces/field")
	if err == nil {
		t.Fatal("expected error for URI with spaces in segment")
	}
}

func TestValidateURISegments_InvalidSegment_ShellInjection(t *testing.T) {
	cases := []string{
		"op://vault/item;rm -rf/field",
		"op://vault/item`whoami`/field",
		"op://vault/item$(cmd)/field",
		"op://vault/item|pipe/field",
		"op://vault/item&bg/field",
	}
	for _, uri := range cases {
		if err := validateURISegments(uri); err == nil {
			t.Errorf("validateURISegments(%q): expected error for shell metacharacter, got nil", uri)
		}
	}
}

func TestValidateURISegments_DotSegments(t *testing.T) {
	cases := []string{
		"op://vault/../traversal/field",
		"op://vault/./current/field",
	}
	for _, uri := range cases {
		if err := validateURISegments(uri); err == nil {
			t.Errorf("validateURISegments(%q): expected error for dot segment, got nil", uri)
		}
	}
}

func TestValidateURISegments_EmptySegmentsOK(t *testing.T) {
	// Double-slash produces empty segments which should be skipped.
	if err := validateURISegments("op://vault//item/field"); err != nil {
		t.Errorf("expected empty segments to be tolerated, got: %v", err)
	}
}

func TestValidateURISegments_ValidFragment(t *testing.T) {
	if err := validateURISegments("op://vault/item/field#subfield"); err != nil {
		t.Errorf("expected valid fragment to pass, got: %v", err)
	}
}

func TestValidateURISegments_InvalidFragment(t *testing.T) {
	err := validateURISegments("op://vault/item/field#bad fragment")
	if err == nil {
		t.Fatal("expected error for invalid fragment")
	}
}

// --- detectCLI / findExecutable ---

func TestDetectCLI_BinaryThatExists(t *testing.T) {
	// "sh" is always available on Unix and macOS.
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}
	result := detectCLI("sh")
	if result != "detected" {
		t.Errorf("expected 'detected' for 'sh', got: %q", result)
	}
}

func TestDetectCLI_BinaryThatDoesNotExist(t *testing.T) {
	result := detectCLI("this-binary-certainly-does-not-exist-xyz-abc-999")
	if result != "not detected" {
		t.Errorf("expected 'not detected' for nonexistent binary, got: %q", result)
	}
}

func TestFindExecutable_ExistingBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}
	path, err := findExecutable("sh")
	if err != nil {
		t.Fatalf("findExecutable('sh'): unexpected error: %v", err)
	}
	if path == "" {
		t.Error("expected non-empty path for 'sh'")
	}
}

func TestFindExecutable_NonExistent(t *testing.T) {
	_, err := findExecutable("nonexistent-binary-xyz-999")
	if err == nil {
		t.Fatal("expected error for nonexistent binary")
	}
	// Should be an exec.ErrNotFound or path error.
	if _, ok := err.(*exec.Error); !ok {
		// LookPath may return various error types; just check non-nil is sufficient.
		_ = err
	}
}

// --- platformBackend ---

func TestPlatformBackend_ReturnsNameAndDesc(t *testing.T) {
	name, desc := platformBackend()
	if name == "" {
		t.Error("expected non-empty name from platformBackend")
	}
	if desc == "" {
		t.Error("expected non-empty desc from platformBackend")
	}
}

func TestPlatformBackend_CurrentPlatform(t *testing.T) {
	name, _ := platformBackend()
	switch runtime.GOOS {
	case "darwin":
		if name != "keychain" {
			t.Errorf("expected 'keychain' on darwin, got: %q", name)
		}
	case "windows":
		if name != "file" {
			t.Errorf("expected 'file' on windows, got: %q", name)
		}
	}
	// Linux defaults to file until a Linux keyring backend is fully registered.
}

// --- readFieldFromStdin ---

func TestReadFieldFromStdin_StripsNewline(t *testing.T) {
	input := "my-secret-value\n"
	result, err := readFieldFromStdin(strings.NewReader(input))
	if err != nil {
		t.Fatalf("readFieldFromStdin: %v", err)
	}
	if string(result) != "my-secret-value" {
		t.Errorf("expected 'my-secret-value', got: %q", string(result))
	}
}

func TestReadFieldFromStdin_StripsCRLF(t *testing.T) {
	input := "my-secret-value\r\n"
	result, err := readFieldFromStdin(strings.NewReader(input))
	if err != nil {
		t.Fatalf("readFieldFromStdin: %v", err)
	}
	if string(result) != "my-secret-value" {
		t.Errorf("expected 'my-secret-value', got: %q", string(result))
	}
}

func TestReadFieldFromStdin_EmptyInput(t *testing.T) {
	result, err := readFieldFromStdin(strings.NewReader(""))
	if err != nil {
		t.Fatalf("readFieldFromStdin: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty result for empty input, got: %q", string(result))
	}
}

func TestReadFieldFromStdin_PreservesInternalNewlines(t *testing.T) {
	// Only trailing newlines are stripped.
	input := "line1\nline2\n"
	result, err := readFieldFromStdin(strings.NewReader(input))
	if err != nil {
		t.Fatalf("readFieldFromStdin: %v", err)
	}
	if string(result) != "line1\nline2" {
		t.Errorf("expected 'line1\\nline2', got: %q", string(result))
	}
}
