//go:build ignore

// Command gen_redaction_patterns regenerates packaging/redaction-patterns.json
// from internal/runner's redactionDefs table (see redact.go), which is the
// single source of truth for credential-shaped patterns.
//
// Run via `go generate ./internal/runner` (see the //go:generate directive
// in redact.go), or directly:
//
//	go run internal/runner/gen_redaction_patterns.go
//
// packaging/ci/scan-no-secret-in-storage.sh is a plain bash script with no
// regex engine dependency — it only does `grep -F` literal substring
// matching against packaging/redaction-patterns.json. Rather than
// maintaining that JSON file by hand (which had drifted from redact.go's
// richer regex table), it is generated here from RedactionPrefixes(), which
// derives one literal prefix per pattern in redactionDefs.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/keylatch/keylatch/internal/runner"
)

func main() {
	prefixes := runner.RedactionPrefixes()

	data, err := json.MarshalIndent(prefixes, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen_redaction_patterns:", err)
		os.Exit(1)
	}
	data = append(data, '\n')

	// This file lives at <repo-root>/internal/runner/gen_redaction_patterns.go;
	// packaging/redaction-patterns.json is two directories up. Resolve via
	// runtime.Caller so this works regardless of the invoking working
	// directory (`go generate` runs from the directive's package directory,
	// but `go run` from an arbitrary cwd should also work).
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		fmt.Fprintln(os.Stderr, "gen_redaction_patterns: could not resolve source path")
		os.Exit(1)
	}
	out := filepath.Join(filepath.Dir(thisFile), "..", "..", "packaging", "redaction-patterns.json")

	if err := os.WriteFile(out, data, 0o644); err != nil { //nolint:gosec // G306: non-secret, repo-tracked codegen output
		fmt.Fprintln(os.Stderr, "gen_redaction_patterns:", err)
		os.Exit(1)
	}
	fmt.Println("gen_redaction_patterns: wrote", out)
}
