package backend_test

import (
	"os"
	"regexp"
	"testing"
)

// getMethodSignature matches a Get(ctx, <name> string) ([]byte, backend.Meta,
// error) method definition, regardless of receiver name/type or the second
// parameter's name (some backends use "path", others "name").
var getMethodSignature = regexp.MustCompile(
	`func \(\w+ \*\w+\) Get\(ctx context\.Context, \w+ string\) \(\[\]byte, backend\.Meta, error\) \{`)

// TestAllBackendsGuardGetWithRunnerOK is a static-source regression test for
// C2: every registered backend's Get() must check runner.OK(ctx) before
// returning plaintext (the LLM-session exfiltration guard).
//
// This is a source check rather than a runtime behavioural test because
// runner.OK (internal/runner/ok.go) is currently a hardcoded stub that
// always returns true — "real approval checking ... is wired in
// separately" per its own doc comment — so there is no way to make it
// return false at runtime yet, and therefore no way to runtime-test "Get
// refuses when runner.OK is false". Mirrors the existing static-grep
// invariant check for the LLM guard override pattern
// (cmd/keylatch/main_e2e_test.go: TestStaticGrepNoOverride). When runner.OK
// gains real logic, this should be supplemented with a runtime table-driven
// test using an injectable OK function.
//
// The "memory" backend is deliberately excluded: it is a test-only, in-
// process backend never registered in backend.Default (see
// internal/backend/all/all.go) and does not use ctx at all.
func TestAllBackendsGuardGetWithRunnerOK(t *testing.T) {
	// Paths are relative to this file's directory (internal/backend/).
	files := map[string]string{
		"awssm":      "awssm/awssm.go",
		"azurekv":    "azurekv/azurekv.go",
		"bw":         "bw/bw.go",
		"doppler":    "doppler/doppler.go",
		"file":       "file/file.go",
		"gcpsm":      "gcpsm/gcpsm.go",
		"infisical":  "infisical/infisical.go",
		"keeper":     "keeper/keeper.go",
		"keychain":   "keychain/keychain.go",
		"lastpass":   "lastpass/lastpass.go",
		"op":         "op/op.go",
		"opconnect":  "opconnect/opconnect.go",
		"protonpass": "protonpass/protonpass.go",
		"vault":      "vault/vault.go",
	}

	for name, rel := range files {
		name, rel := name, rel
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(rel)
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}
			src := string(data)

			loc := getMethodSignature.FindStringIndex(src)
			if loc == nil {
				t.Fatalf("%s: no Get(ctx context.Context, <arg> string) ([]byte, backend.Meta, error) method found", rel)
			}

			// The guard must appear near the top of the method body — look
			// within the first 400 bytes after the signature (every guarded
			// backend puts it as the first or near-first statement).
			end := loc[1] + 400
			if end > len(src) {
				end = len(src)
			}
			body := src[loc[1]:end]
			if !regexp.MustCompile(`runner\.OK\(ctx\)`).MatchString(body) {
				t.Errorf("%s: Get() does not check runner.OK(ctx) near the top of the method body — "+
					"plaintext could be returned without the LLM-session guard (C2)", rel)
			}
		})
	}
}
