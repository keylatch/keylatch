package keychain_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestNoShDashC verifies that no "sh -c" invocations exist in internal/backend/.
// Backend code must never invoke sh -c.
func TestNoShDashC(t *testing.T) {
	backendDir := findBackendDir(t)

	err := walkGoFiles(backendDir, func(path string, content []byte) error {
		lines := bytes.Split(content, []byte("\n"))
		for i, line := range lines {
			if bytes.Contains(line, []byte(`"sh"`)) &&
				bytes.Contains(line, []byte(`"-c"`)) {
				t.Errorf("%s:%d: found sh -c invocation: %s",
					path, i+1, strings.TrimSpace(string(line)))
			}
			// Also check for string literals containing "sh -c".
			if bytes.Contains(line, []byte(`sh -c`)) {
				t.Errorf("%s:%d: found 'sh -c' string: %s",
					path, i+1, strings.TrimSpace(string(line)))
			}
		}
		return nil
	})

	if err != nil {
		t.Fatalf("file walk: %v", err)
	}
}

// TestNoOsExecOutsideExec verifies that "os/exec" is not imported in internal/backend/.
// All exec calls must go through internal/exec, never os/exec directly in backends.
func TestNoOsExecOutsideExec(t *testing.T) {
	backendDir := findBackendDir(t)

	err := walkGoFiles(backendDir, func(path string, content []byte) error {
		lines := bytes.Split(content, []byte("\n"))
		for i, line := range lines {
			if bytes.Contains(line, []byte(`"os/exec"`)) {
				t.Errorf("%s:%d: found os/exec import in backend package: %s",
					path, i+1, strings.TrimSpace(string(line)))
			}
		}
		return nil
	})

	if err != nil {
		t.Fatalf("file walk: %v", err)
	}
}

// findBackendDir returns the absolute path to internal/backend/ relative to
// the repository root, using the test file's path as an anchor.
func findBackendDir(t *testing.T) string {
	t.Helper()
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file path")
	}
	// testFile is .../internal/backend/keychain/static_grep_test.go
	// Go up to internal/backend/
	backendDir := filepath.Join(filepath.Dir(testFile), "..")
	abs, err := filepath.Abs(backendDir)
	if err != nil {
		t.Fatalf("resolve backend dir: %v", err)
	}
	return abs
}

// walkGoFiles walks all non-test .go files under root, calling fn for each.
// Test files (_test.go) are excluded because they may contain the patterns
// they are testing for (e.g., the grep test searches for "sh -c" and
// necessarily contains that string in its own source).
func walkGoFiles(root string, fn func(path string, content []byte) error) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// Only scan non-test Go files.
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return fn(path, content)
	})
}
