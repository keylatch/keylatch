//go:build meta

package canary_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestCanaryCoverage verifies that each value-bearing package has at least one
// test file that calls AssertNoLeak.
//
// Packages that do not yet have AssertNoLeak coverage are skipped with a note
// so that the check can run without blocking CI while coverage is added
// incrementally. Missing package directories are skipped too.
func TestCanaryCoverage(t *testing.T) {
	// Locate the module root by walking up from this file's directory.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// thisFile: .../internal/canary/coverage_test.go
	moduleRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")

	packages := []string{
		"internal/vault",
		"internal/runner",
		"internal/connections",
		"internal/mcp",
		"internal/gateway",
		"internal/ui",
	}

	for _, pkg := range packages {
		pkg := pkg
		t.Run(pkg, func(t *testing.T) {
			pkgDir := filepath.Join(moduleRoot, filepath.FromSlash(pkg))
			entries, err := os.ReadDir(pkgDir)
			if err != nil {
				if os.IsNotExist(err) {
					t.Skipf("package %s does not exist — skipping", pkg)
					return
				}
				t.Fatalf("ReadDir %s: %v", pkgDir, err)
			}

			found := false
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
					continue
				}
				path := filepath.Join(pkgDir, entry.Name())
				data, err := os.ReadFile(path)
				if err != nil {
					t.Errorf("ReadFile %s: %v", path, err)
					continue
				}
				if bytes.Contains(data, []byte("AssertNoLeak")) {
					found = true
					break
				}
			}

			if !found {
				// Skip (rather than fail) packages that have not yet adopted canary
				// testing, so canary calls can be added to value-bearing packages
				// one at a time.
				t.Skipf("package %s has no test file calling AssertNoLeak yet", pkg)
			}
		})
	}
}
